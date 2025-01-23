use rocket::form::FromFormField;
use std::fmt;

#[derive(Debug, PartialEq, Eq, FromFormField)]
#[repr(i32)]
pub enum UserStatus {
    Inactive = 0,
    Active = 1,
}

impl TryFrom<i8> for UserStatus {
    type Error = &'static str;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(UserStatus::Inactive),
            1 => Ok(UserStatus::Active),
            _ => Err("Invalid user status"),
        }
    }
}

impl From<UserStatus> for i8 {
    fn from(status: UserStatus) -> Self {
        status as i8
    }
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            UserStatus::Inactive => write!(f, "Inactive"),
            UserStatus::Active => write!(f, "Active"),
        }
    }
}