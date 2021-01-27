// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn main() {
    {
        let mut groups = vec![];
        let ret = nc::getgroups(0, &mut groups);
        assert!(ret.is_ok());
        let total_num = ret.unwrap();
        groups.resize(total_num as usize, 0);

        let ret = nc::getgroups(total_num, &mut groups);
        assert!(ret.is_ok());
        assert_eq!(ret, Ok(total_num));
    }

    {
        let mut groups = vec![0; 8];
        let mut ret = nc::getgroups(groups.len() as i32, &mut groups);
        while ret.is_err() && ret == Err(nc::EINVAL) {
            groups.resize(groups.len() * 2, 0);
            ret = nc::getgroups(groups.len() as i32, &mut groups);
        }
    }
}
