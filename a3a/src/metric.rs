use std::fmt;
use fcn::Function;

pub struct Metric {
    pub bb: u32,
    pub div: u32,
    pub xor: u32,
    pub sqrt: u32,
    pub op: u32,
    pub constant: u32,
    pub i_call: u32,
    pub l_call: u32,
    pub stack: i32,
    pub references: u32,
}

impl fmt::Display for Metric {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bb:{: <3} div:{: <3} xor:{: <3} sqrt:{: <3} op:{: <3} constant:{: <3} i_call:{: <3} l_call:{: <3} stack:{: <3} ref:{: <3}", 
               self.bb, self.div, self.xor, self.sqrt, self.op, self.constant, self.i_call, self.l_call, self.stack, self.references)
    }
}

impl Metric {
    pub fn new(function: &Function) -> Metric {
        // TODO init metric here
        for (_, bb) in &function.blocks {
            let mut cur: u64 = 0;
            let mut start: u64 = 0;
            while cur < bb.end {
            }
        }
        Metric {bb:0,div:0,xor:0,sqrt:0,op:0,constant:0,i_call:0,l_call:0,stack:0,references:0}
    }
}
