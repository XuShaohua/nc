extern crate nc;

fn main() {
    match nc::getcwd() {
        Ok(pwd) => println!("pwd: {}", String::from_utf8(pwd).unwrap()),
        Err(err) => eprintln!("err: {}", err),
    }

    let _ = nc::chdir("/opt");

    match nc::getcwd() {
        Ok(pwd) => println!("pwd: {}", String::from_utf8(pwd).unwrap()),
        Err(err) => eprintln!("err: {}", err),
    }
}
