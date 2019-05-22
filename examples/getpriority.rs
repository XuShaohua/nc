
extern crate nc;

fn main() {
    let _ret = nc::setpriority(nc::PRIO_PROCESS, 0, -5)
        .expect("Failed to set priority to -5!");
    let prio = nc::getpriority(nc::PRIO_PROCESS, 0);
    println!("prio: {:?}", prio);
}
