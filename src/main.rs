use std::io::{Cursor, Seek, SeekFrom};
use std::any::Any;
use base64::{decode};
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};

// [Security Decriptor MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d?redirectedfrom=MSDN)
// #[derive(Clone)]
struct SecurityDescriptor{
    Revision: u8,
    Sbz1: u8,
    Control: u16,
    OffsetOwner: u32,
    OffsetGroup: u32,
    OffsetSacl: u32,
    OffsetDacl: u32,
    OwnerSid: Option<SID>, // possible not present
    GroupSid: Option<SID>,
    Sacl: Option<ACL>,
    Dacl: Option<ACL>
}
impl SecurityDescriptor{
    fn new(bin: Vec<u8>) -> Self{
        let mut rdr:Cursor<Vec<u8>> = Cursor::new(bin.clone());

        // can replace byteorder with [x..y] and to_le_bytes
        let mut sd = SecurityDescriptor{
            Revision: rdr.read_u8().unwrap(),
            Sbz1: rdr.read_u8().unwrap(),
            Control: rdr.read_u16::<LittleEndian>().unwrap(),
            OffsetOwner: rdr.read_u32::<LittleEndian>().unwrap(),
            OffsetGroup: rdr.read_u32::<LittleEndian>().unwrap(),
            OffsetSacl: rdr.read_u32::<LittleEndian>().unwrap(),
            OffsetDacl: rdr.read_u32::<LittleEndian>().unwrap(),
            OwnerSid: None,
            GroupSid: None,
            Sacl: None,
            Dacl: None
        };

        sd.OwnerSid = Some(SID::new(bin[sd.OffsetOwner as usize..sd.OffsetGroup as usize].to_vec()));
        sd.GroupSid = Some(SID::new(bin[sd.OffsetOwner as usize..sd.OffsetGroup as usize].to_vec()));

        sd.Dacl =  Some(ACL::new(bin[sd.OffsetDacl as usize..].to_vec()));

        return sd;
    }
}

// [SID MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861)
#[derive(Clone)]
struct SID{
    Revision: u8,
    SubAuthorityCount: u8,
    IdentifierAuthority: u64, // 6 byte field
                              // [Identifier Authority MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c6ce4275-3d90-4890-ab3a-514745e4637e)
    SubAuthority: Vec<u32>
}
impl SID{
    // constructor
    pub fn new(bin: Vec<u8>) -> Self{
        let mut rdr:Cursor<Vec<u8>> = Cursor::new(bin);
        let mut sid = SID{
            Revision: rdr.read_u8().unwrap(),
            SubAuthorityCount: rdr.read_u8().unwrap(),
            IdentifierAuthority: (((rdr.read_u32::<BigEndian>().unwrap() as u64) << 32) | (rdr.read_u16::<BigEndian>().unwrap() as u64)), // combine 4 byte and 2 byte
            SubAuthority: vec![]
        };
        // rust range notation 0 -> n-1
        for _ in 0..sid.SubAuthorityCount {
            sid.SubAuthority.push(rdr.read_u32::<LittleEndian>().unwrap());
        }
        return sid;
    }

    // [SID String MSDN](https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-components)
    pub fn to_string(&self) -> String {
        let mut sid: String = String::new();
        sid.push_str(&format!("SID String: S-{}-{}",self.Revision,self.IdentifierAuthority));

        for n in 0..self.SubAuthority.len(){
            sid.push_str(&format!("-{}", self.SubAuthority[n]));
        }

        return sid;
    }

    // useful for searching LDAP objectSid
    pub fn to_base64(&self) -> String{
        let mut bin: Vec<u8> = vec![];
        bin.push(self.Revision);
        bin.push(self.SubAuthorityCount);
        // convert u32 to [u8]
        let ia_bytes = self.IdentifierAuthority.to_be_bytes();
        // skip first byte of SubAuthority due to padding, u48 inside u64 
        for n in &ia_bytes[2..]{
            bin.push(*n);
        }

        // vec[u32] to vec[u8]
        for n in &self.SubAuthority{
            let sa_bytes = n.swap_bytes().to_be_bytes();
            for i in sa_bytes{
                bin.push(i);
            }
        }

        return format!("{}", base64::encode(&bin));
    }

    pub fn size(&self) -> u8{
        return 2 + 8 + (4*self.SubAuthorityCount);
    }
}

// [ACL MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428?redirectedfrom=MSDN)
//#[derive(Clone)]
struct ACL{
    AclRevision: u8,
    Sbz1: u8,
    AclSize: u16,
    AceCount: u16,
    Sbz2: u16,
    ACEList: Vec<Box<dyn ACEType>>
}
impl ACL{
    // constructor
    pub fn new(bin: Vec<u8>) -> Self{
        let mut rdr:Cursor<Vec<u8>> = Cursor::new(bin.clone());
        let acl_revision = rdr.read_u8().unwrap();
        let sbz1 = rdr.read_u8().unwrap();
        let acl_size = rdr.read_u16::<LittleEndian>().unwrap(); 
        let ace_count = rdr.read_u16::<LittleEndian>().unwrap(); 
        let sbz2 = rdr.read_u16::<LittleEndian>().unwrap();

        // TODO: PRIORITY parse DACL and fill with aces
        // loop over ACE enteries
        let mut ace_list:Vec<Box<dyn ACEType>> = vec![];
        let mut offset = 8; // start offset after ACL data
        for n in 0..ace_count{
            let ace_type = bin[offset];
            match ace_type{
                ACEHeader::ACCESS_ALLOWED_ACE_TYPE => ace_list.push(Box::new(ACCESS_ALLOWED_ACE::new(bin[offset..].to_vec()))),
                ACEHeader::ACCESS_ALLOWED_OBJECT_ACE_TYPE => ace_list.push(Box::new(ACCESS_ALLOWED_OBJECT_ACE::new(bin[offset..].to_vec()))),
                _ => ()
            }


            // DEBUGGING: stopping at first ace since that is the only type implemented
            if n==1 {
                break;
            } 
            offset += ace_list[n as usize].size() as usize;
            // println!("{}",offset);
        }

        let acl = ACL{
            AclRevision: acl_revision,
            Sbz1: sbz1,
            AclSize: acl_size, 
            AceCount: ace_count, 
            Sbz2: sbz2,
            ACEList: ace_list
        };
        return acl;
    }
}

// [ACCESS_MASK Spec MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b)
#[derive(Clone)]
struct ACCESS_MASK{
    Mask: u32
}
impl ACCESS_MASK{
    const GENERIC_READ:u32            = 0x80000000;
    const GENERIC_WRITE:u32           = 0x40000000;
    const GENERIC_EXECUTE:u32         = 0x20000000;
    const GENERIC_ALL:u32             = 0x10000000;
    const MAXIMUM_ALLOWED:u32         = 0x02000000;
    const ACCESS_SYSTEM_SECURITY:u32  = 0x01000000;
    const SYNCHRONIZE:u32             = 0x00100000;
    const WRITE_OWNER:u32             = 0x00080000;
    const WRITE_DACL:u32              = 0x00040000;
    const READ_CONTROL:u32            = 0x00020000;
    const DELETE:u32                  = 0x00010000;

    pub fn new(bin: Vec<u8>) -> Self{
        let mut rdr:Cursor<Vec<u8>> = Cursor::new(bin);
        let mask = ACCESS_MASK{
            Mask: rdr.read_u32::<LittleEndian>().unwrap()
        };
        return mask;
    }
}

// [ACE Header Spec MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586)
#[derive(Clone)]
struct ACEHeader{
    AceType: u8,
    AceFlags: u8,
    AceSize: u16
}
impl ACEHeader{
    // constructor
    pub fn new(bin: Vec<u8>) -> Self{
        let mut rdr:Cursor<Vec<u8>> = Cursor::new(bin);
        let ace = ACEHeader{
            AceType: rdr.read_u8().unwrap(),
            AceFlags: rdr.read_u8().unwrap(),
            AceSize: rdr.read_u16::<LittleEndian>().unwrap()
        };
        return ace;
    }

    const ACCESS_ALLOWED_ACE_TYPE:u8 = 0x00;
    const ACCESS_DENIED_ACE_TYPE:u8 = 0x01;
    const SYSTEM_AUDIT_ACE_TYPE:u8 = 0x02;
    const SYSTEM_ALARM_ACE_TYPE:u8 = 0x03;
    const ACCESS_ALLOWED_COMPOUND_ACE_TYPE:u8 = 0x04;
    const ACCESS_ALLOWED_OBJECT_ACE_TYPE:u8 = 0x05;
    const ACCESS_DENIED_OBJECT_ACE_TYPE:u8 = 0x06;
    const SYSTEM_AUDIT_OBJECT_ACE_TYPE:u8 = 0x07;
    const SYSTEM_ALARM_OBJECT_ACE_TYPE:u8 = 0x08;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE:u8 = 0x09;
    const ACCESS_DENIED_CALLBACK_ACE_TYPE:u8 = 0x0A;
    const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:u8 = 0x0B;
    const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:u8 = 0x0C;
    const SYSTEM_AUDIT_CALLBACK_ACE_TYPE:u8 = 0x0D;
    const SYSTEM_ALARM_CALLBACK_ACE_TYPE:u8 = 0x0E;
    const SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:u8 = 0x0F;
    const SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:u8 = 0x10;
    const SYSTEM_MANDATORY_LABEL_ACE_TYPE:u8 = 0x11;
    const SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:u8 = 0x12;
    const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:u8 = 0x13;
}

// ACE trait object, used to add all ACE's to the same Vec collection
// probably a more idiomatic way to handle this
trait ACEType{
    fn ace_type(&self) -> u8;
    fn size(&self)->u16; // size in bytes (including header)
    fn as_any(&self) -> &dyn Any;
}

// [ACCESS_ALLOWED_ACE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb)
#[derive(Clone)]
struct ACCESS_ALLOWED_ACE{
    Header: ACEHeader,
    Mask: ACCESS_MASK,
    Sid: SID
}
impl ACEType for ACCESS_ALLOWED_ACE{
    fn ace_type(&self) -> u8{
        return ACEHeader::ACCESS_ALLOWED_ACE_TYPE;
    }

    fn size(&self) -> u16{
        return self.Header.AceSize; 
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
impl ACCESS_ALLOWED_ACE{
    fn new(bin: Vec<u8>) -> Self{
        let header = ACEHeader::new(bin[..4].to_vec());
        let mask = ACCESS_MASK::new(bin[4..8].to_vec());
        let sid = SID::new(bin[8..].to_vec());

        let ace = ACCESS_ALLOWED_ACE{
            Header: header,
            Mask: mask,
            Sid: sid
        };
        return ace;
    }
}

// [ACCESS_ALLOWED_OBJECT_ACE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe)
#[derive(Clone)]
struct ACCESS_ALLOWED_OBJECT_ACE{
    Header: ACEHeader,
    Mask: ACCESS_MASK,
    Flags: u32,
    ObjectType: Option<u128>, // optional fields
    InheritedObjectType: Option<u128>,
    Sid: SID
}
impl ACEType for ACCESS_ALLOWED_OBJECT_ACE{
    fn ace_type(&self) -> u8{
        return ACEHeader::ACCESS_ALLOWED_OBJECT_ACE_TYPE;
    }

    fn size(&self) -> u16{
        return self.Header.AceSize;
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
impl ACCESS_ALLOWED_OBJECT_ACE{
    fn new(bin: Vec<u8>) -> Self{
        let header = ACEHeader::new(bin[..4].to_vec());
        let mask = ACCESS_MASK::new(bin[4..8].to_vec());

        let mut rdr:Cursor<Vec<u8>> = Cursor::new(bin.clone());
        rdr.seek(SeekFrom::Start(8)); // skip header + access mask

        let flags = rdr.read_u32::<LittleEndian>().unwrap();

        // if flags are present, then 0 bytes of space are taken up
        let mut object_type = None;
        if (flags & 0x00000001 == 0x00000001){
            object_type = Some(rdr.read_u128::<LittleEndian>().unwrap());
        }

        let mut inherited_object_type = None;
        if (flags & 0x00000002 == 0x00000002){
            inherited_object_type = Some(rdr.read_u128::<LittleEndian>().unwrap());
        }

        // get sid from offset
        let sid = SID::new(bin[rdr.position() as usize..].to_vec());

        let ace = ACCESS_ALLOWED_OBJECT_ACE{
            Header: header,
            Mask: mask,
            Flags: flags,
            ObjectType: object_type,
            InheritedObjectType: inherited_object_type,
            Sid: sid
        };
        return ace;
    }
}

fn main() {
    let b64str: &str = "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";
    let bin = decode(b64str).unwrap();

    // TODO: turn main into constructor for SecurityDescriptor
    // let mut rdr:Cursor<Vec<u8>> = Cursor::new(bin.clone());
    
    let mut sd = SecurityDescriptor::new(bin.clone());
    // println!("Security Descriptor\nRevision: {:X?}\nSbz1: {:X?}\nControl: {:b}\nOffsetOwner: {:X?}\nOffsectGroup: {:X?}\nOffsetSacl: {:X?}\nOffsetDacl: {:X?}\n", 
    // sd.Revision,
    // sd.Sbz1,
    // sd.Control,
    // sd.OffsetOwner,
    // sd.OffsetGroup,
    // sd.OffsetSacl,
    // sd.OffsetDacl);

    println!("Owner SID String: {}",sd.OwnerSid.clone().unwrap().to_string());
    println!("Owner SID Base64: {}\n",sd.OwnerSid.clone().unwrap().to_base64());
    println!("SID String: {}",sd.GroupSid.clone().unwrap().to_string());
    println!("SID Base64: {}\n",sd.GroupSid.clone().unwrap().to_base64());

    // println!("Dacl\nAclRevision: {:X?}\nSbz1: {:X?}\nAclSize: {:X?}\nAceCount: {:X?}\nSbz2: {:X?}\n",
    // dacl.AclRevision,
    // dacl.Sbz1,
    // dacl.AclSize,
    // dacl.AceCount,
    // dacl.Sbz2);

    // let aceheader1 = ACEHeader::new(bin[(sd.OffsetDacl as usize)+8..].to_vec());
    // println!("ACE\nAceType: {:X?}\nAclFlags: {:X?}\nAceSize: {:X?}\n",aceheader1.AceType,aceheader1.AceFlags,aceheader1.AceSize);

    // println!("{}",ACEHeader::get_type(bin[(sd.OffsetDacl as usize)+8..].to_vec()));

    // downcast to type https://www.reddit.com/r/rust/comments/kkap4e/how_to_cast_a_boxdyn_mytrait_to_an_actual_struct/
    println!("{:X?}",sd.Dacl.as_ref().unwrap().ACEList[0].as_any().downcast_ref::<ACCESS_ALLOWED_OBJECT_ACE>().unwrap().Flags);

    println!("{:X?}",sd.Dacl.as_ref().unwrap().ACEList[0].as_any().downcast_ref::<ACCESS_ALLOWED_OBJECT_ACE>().unwrap().Sid.to_string());

    /*
    # Sanity Check with python impacket
    # https://github.com/SecureAuthCorp/impacket/blob/a98b7b97416650cd2a23e480a69be61b65ec2f0a/impacket/ldap/ldaptypes.py
    from impacket.ldap import ldaptypes
    import base64

    b64 = "[BASE64-nTSecurityDescriptor]"
    bin =  base64.b64decode(b64)
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(bin)

    # example checking first ace Mask
    sd.fields['Dacl'].aces[0].fields['Ace'].fields['Mask'].hasPriv(0x00000020)
    */
}
