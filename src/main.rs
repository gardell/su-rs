const PAM_SERVICE: &str = "su-rs";
const DEFAULT_SHELL: &str = "/bin/sh";
const SUDO_GROUP_NAME: &str = "sudo";
const DEFAULT_LOGIN_PATH: &str = "/usr/local/bin:/bin:/usr/bin";
const DEFAULT_ROOT_LOGIN_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin";

use quick_error::quick_error;
quick_error! {
    #[derive(Debug)]
    pub enum Error {
        ExpectedLine {}
        GetCurrentUsername {}
        GetUserGroups {}
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
        UserNotInSudoGroup {}
        VarError(err: std::env::VarError) {
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
    let current_username = users::get_current_username().ok_or(Error::GetCurrentUsername)?;
    users::get_user_groups(
        &current_username,
        users::get_user_by_name(&current_username)
            .ok_or(Error::NoSuchUser)?
            .primary_group_id(),
    )
    .ok_or(Error::GetUserGroups)?
    .into_iter()
    .find(|group| group.name().to_str() == Some(SUDO_GROUP_NAME))
    .ok_or(Error::UserNotInSudoGroup)?;

    use clap::load_yaml;
    let yaml = load_yaml!("cli.yml");
    let matches = clap::App::from_yaml(yaml).get_matches();

    let command = std::ffi::CString::new(matches.value_of("command").unwrap_or(DEFAULT_SHELL))?;
    let shell = matches.value_of("shell").unwrap_or(DEFAULT_SHELL);
    let arguments = matches.values_of("arguments");
    let username = matches.value_of("user").unwrap_or("root");

    let user = users::get_user_by_name(username).ok_or(Error::NoSuchUser)?;

    use users::os::unix::UserExt;
    let env = std::iter::once(("TERM", std::borrow::Cow::Owned(std::env::var("TERM")?)))
        .chain(std::iter::once(("HOME", user.home_dir().to_string_lossy())))
        .chain(std::iter::once(("SHELL", shell.into())))
        .chain(std::iter::once(("USER", username.into())))
        .chain(std::iter::once(("LOGNAME", username.into())))
        .chain(std::iter::once((
            "PATH",
            if user.uid() == 0 {
                DEFAULT_ROOT_LOGIN_PATH
            } else {
                DEFAULT_LOGIN_PATH
            }
            .into(),
        )))
        // TODO: shell escape?
        .map(|(key, value)| std::ffi::CString::new(format!("{}={}", key, value)))
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
