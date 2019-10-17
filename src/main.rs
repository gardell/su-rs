const PAM_SERVICE: &str = "su-rs";
const DEFAULT_SHELL: &str = "/bin/sh";

use quick_error::quick_error;
quick_error! {
    #[derive(Debug)]
    pub enum Error {
        ExpectedLine {}
        GetCurrentUsername {}
        Io(err: std::io::Error) {
            from()
        }
        Nix(err: nix::Error) {
            from()
        }
        NulError(err: std::ffi::NulError) {
            from()
        }
        NoSuchUser {}
        Pam(err: pam::PamError) {
            from()
        }
    }
}

struct ScopedTcSetattr<T: std::os::unix::io::AsRawFd> {
    handle: T,
    initial: nix::sys::termios::Termios,
}

impl<T: std::os::unix::io::AsRawFd> ScopedTcSetattr<T> {
    pub fn new(
        handle: T,
        f: impl FnOnce(&nix::sys::termios::Termios) -> nix::sys::termios::Termios,
    ) -> Result<Self, Error> {
        let initial = nix::sys::termios::tcgetattr(handle.as_raw_fd())?;
        nix::sys::termios::tcsetattr(
            handle.as_raw_fd(),
            nix::sys::termios::SetArg::TCSAFLUSH,
            &f(&initial),
        )?;

        Ok(Self { handle, initial })
    }
}

impl<T: std::os::unix::io::AsRawFd> Drop for ScopedTcSetattr<T> {
    fn drop(&mut self) {
        let result = nix::sys::termios::tcsetattr(
            self.handle.as_raw_fd(),
            nix::sys::termios::SetArg::TCSAFLUSH,
            &self.initial,
        );
        debug_assert!(result.is_ok(), "tcsetattr failed = {:?}", result);
    }
}

fn main() -> Result<(), Error> {
    use clap::load_yaml;
    let yaml = load_yaml!("cli.yml");
    let matches = clap::App::from_yaml(yaml).get_matches();

    let command = std::ffi::CString::new(matches.value_of("command").unwrap_or(DEFAULT_SHELL))?;
    let shell = matches.value_of("shell").unwrap_or(DEFAULT_SHELL);
    let arguments = matches.values_of("arguments");

    let user = users::get_user_by_name(matches.value_of("user").unwrap_or("root"))
        .ok_or(Error::NoSuchUser)?;

    use users::os::unix::UserExt;
    let env = std::env::vars()
        // TODO: shell escape?
        .map(|(key, value)| format!("{}={}", key, value))
        .chain(std::iter::once(format!(
            "HOME={}",
            user.home_dir().to_string_lossy()
        )))
        .chain(std::iter::once(format!("SHELL={}", shell)))
        .map(std::ffi::CString::new)
        // TODO: Making the assumption the last env variables override whatever is set
        .collect::<Result<Vec<_>, _>>()?;

    let arguments = arguments
        .into_iter()
        .flat_map(|arguments| arguments.into_iter())
        .map(std::ffi::CString::new)
        .collect::<Result<Vec<_>, _>>()?;

    let password = {
        let _setattr = ScopedTcSetattr::new(std::io::stdin(), |termios| {
            let mut termios = termios.clone();
            termios
                .local_flags
                .remove(nix::sys::termios::LocalFlags::ECHO);
            termios
        })?;

        eprint!("Password: ");
        use std::io::BufRead;
        std::io::stdin()
            .lock()
            .lines()
            .next()
            .ok_or(Error::ExpectedLine)??
    };
    eprintln!();

    let current_username = users::get_current_username().ok_or(Error::GetCurrentUsername)?;
    let mut auth = pam::Authenticator::with_password(PAM_SERVICE)?;
    auth.get_handler()
        .set_credentials(current_username.to_string_lossy(), password);

    auth.authenticate()?;
    auth.open_session()?;

    nix::unistd::setgid(nix::unistd::Gid::from_raw(user.primary_group_id()))?;
    nix::unistd::setuid(nix::unistd::Uid::from_raw(user.uid()))?;

    nix::unistd::execve(&command, arguments.as_slice(), env.as_slice())?;

    Ok(())
}
