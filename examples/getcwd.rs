extern crate nc;

fn main() {
    match nc::getcwd() {
        Ok(pwd) => println!("pwd: {:?}", String::from_utf8(pwd)),
        Err(err) => eprintln!("err: {}", err),
    }
}
