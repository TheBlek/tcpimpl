#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
pub struct Addr {
    pub ip: [u8; 4],
    pub port: u16,
}

impl From<([u8; 4], u16)> for Addr {
    fn from((ip, port): ([u8; 4], u16)) -> Self {
        Self { ip, port }
    }
}

impl TryFrom<(&str, u16)> for Addr {
    type Error = anyhow::Error;

    fn try_from((ip, port): (&str, u16)) -> Result<Self, Self::Error> {
        let address = ip
            .split('.')
            .filter_map(|s| s.parse::<u8>().ok())
            .collect::<Vec<_>>()[..4]
            .try_into()?;
        Ok(Addr {
            ip: address,
            port,
        })
    }
}

impl TryFrom<&str> for Addr {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let mut iter = value.split(':');
        let address = iter
            .next()
            .unwrap()
            .split('.')
            .filter_map(|s| s.parse::<u8>().ok())
            .collect::<Vec<_>>()[..4]
            .try_into()?;
        let port = iter.next().unwrap().parse()?;
        Ok(Addr { ip: address, port })
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct ConnectionId {
    pub local: Addr,
    pub remote: Addr,
}
