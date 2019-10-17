# su-rs
A hybrid `su`/`sudo` client written in Rust. Lets anyone belonging to the group `sudo` perform super-user actions by authenticating using *their own* credentials.

## Usage
### Build
```sh
# `debug` mode
./build.sh
# `release` mode
TARGET=release ./build.sh
```

### Run
```sh
# `debug` artifact
target/debug/su-rs
# `release` artifact
target/release/su-rs
```
