use std::sync::atomic::{AtomicPtr, Ordering};

use chrono::prelude::*;

static mut NTP_OFFSET: AtomicPtr<chrono::Duration> = AtomicPtr::new(std::ptr::null_mut());
static mut LAST_CHECK: AtomicPtr<DateTime<Utc>> = AtomicPtr::new(std::ptr::null_mut());

pub fn unix() -> i64 {
    now().timestamp()
}

pub fn now() -> DateTime<Utc> {
    let ts = Utc::now();

    unsafe {
        let last_check = LAST_CHECK.load(Ordering::SeqCst);

        if (last_check.is_null() || (*last_check).time() < ts.time() - chrono::Duration::hours(1))
            && update_last_checked(last_check, ts)
        {
            update_ntp_offset();
        }
    }

    let offset = ntp_offset();

    ts + offset
}

fn update_ntp_offset() {
    loop {
        let stime = chrono::Utc::now();

        let ntp_server =
            std::env::var("SELF_NTP").unwrap_or_else(|_| "time.google.com:123".to_string());

        match ntp::request(ntp_server) {
            Ok(response) => {
                // calculate the ntp offset
                let dtime = chrono::Utc::now() - stime;
                let rtime = chrono::Duration::seconds(response.recv_time.sec as i64)
                    + chrono::Duration::nanoseconds(response.recv_time.frac as i64);
                let otime = chrono::Duration::seconds(response.orig_time.sec as i64)
                    + chrono::Duration::nanoseconds(response.orig_time.frac as i64);

                let offset = ((rtime - otime) + dtime) / 2;

                unsafe {
                    NTP_OFFSET.store(Box::into_raw(Box::new(offset)), Ordering::SeqCst);
                }

                return;
            }
            Err(err) => {
                println!("ntp lookup failed with: {}", err);
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        };
    }
}

fn ntp_offset() -> chrono::Duration {
    unsafe {
        loop {
            let offset = NTP_OFFSET.load(Ordering::SeqCst);
            if !offset.is_null() {
                return *offset;
            }

            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

fn update_last_checked(checked: *mut DateTime<Utc>, current_timestamp: DateTime<Utc>) -> bool {
    unsafe {
        LAST_CHECK
            .compare_exchange(
                checked,
                Box::into_raw(Box::new(current_timestamp)),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_unix() {
        unix();
    }
}
