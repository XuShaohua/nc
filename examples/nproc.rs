// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

pub fn get_num_cpu() -> Result<u16, nc::Errno> {
    let mut set = [0; 128];
    set[0] = 1;

    unsafe {
        nc::sched_getaffinity(0, set.len(), &mut set)?;
    }

    let mut count = 0;
    for item in set.iter() {
        let mut item = *item;
        while item > 0 {
            item &= item - 1;
            count += 1;
        }
    }

    Ok(count)
}

fn main() {
    println!("num of cpu: {}", get_num_cpu().unwrap());
}
