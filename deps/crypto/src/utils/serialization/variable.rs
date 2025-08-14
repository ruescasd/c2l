use crate::utils::serialization::{FDeserializable, FSerializable};
use crate::utils::Error;

pub trait VSer: VSerializable + VDeserializable {}
impl<T: VSerializable + VDeserializable> VSer for T {}

// the length of the prepended bytes that specify the length of the serialized data
pub type LengthU = u32;
pub const LENGTH_BYTES: usize = size_of::<LengthU>();

pub trait VSerializable: Sized {
    fn ser(&self) -> Vec<u8>;
}

pub trait VDeserializable: Sized {
    fn deser(buffer: &[u8]) -> Result<Self, Error>;
}

impl<T: VSerializable> VSerializable for &T {
    fn ser(&self) -> Vec<u8> {
        T::ser(self)
    }
}

impl<T: VSerializable> VSerializable for Vec<T> {
    fn ser(&self) -> Vec<u8> {
        let mut ret = vec![];
        for item in self {
            let bytes = item.ser();
            let len: LengthU = bytes.len().try_into().expect("Length conversion failed");
            ret.extend_from_slice(&len.to_be_bytes());
            ret.extend(bytes);
        }

        ret
    }
}

impl<T: VDeserializable> VDeserializable for Vec<T> {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let mut bytes = buffer;
        let mut ret: Vec<Result<T, Error>> = vec![];
        while !bytes.is_empty() {
            let len_bytes: [u8; LENGTH_BYTES] = bytes[0..LENGTH_BYTES].try_into()?;
            let len: usize = LengthU::from_be_bytes(len_bytes)
                .try_into()
                .expect("Length conversion failed");
            ret.push(T::deser(&bytes[LENGTH_BYTES..LENGTH_BYTES + len]));
            bytes = &bytes[LENGTH_BYTES + len..]
        }

        let ret: Result<Vec<T>, Error> = ret.into_iter().collect::<Result<Vec<T>, Error>>();
        ret
    }
}

impl<T: VSerializable, const N: usize> VSerializable for [T; N] {
    fn ser(&self) -> Vec<u8> {
        let mut ret = vec![];

        for v in self {
            let bytes = v.ser();
            let len: LengthU = bytes.len().try_into().expect("Length conversion failed");
            ret.extend_from_slice(&len.to_be_bytes());
            ret.extend(bytes);
        }

        ret
    }
}

impl<T: VDeserializable, const N: usize> VDeserializable for [T; N] {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let mut bytes = buffer;
        let mut ret: Vec<Result<T, Error>> = vec![];

        for _ in 0..N {
            let len_bytes: [u8; LENGTH_BYTES] = bytes[0..LENGTH_BYTES].try_into()?;
            let len: usize = LengthU::from_be_bytes(len_bytes)
                .try_into()
                .expect("Length conversion failed");
            ret.push(T::deser(&bytes[LENGTH_BYTES..LENGTH_BYTES + len]));
            bytes = &bytes[LENGTH_BYTES + len..];
        }

        if !bytes.is_empty() {
            return Err(Error::DeserializationError(
                "Input bytes did factor to N chunks".to_string(),
            ));
        }

        let ts: Vec<T> = ret.into_iter().collect::<Result<Vec<T>, Error>>()?;
        let ret: Result<[T; N], Error> = ts.try_into().map_err(|_| {
            Error::DeserializationError("Failed converting Vec<T> to [T; N]".to_string())
        });

        ret
    }
}

#[derive(Debug)]
pub struct LargeVector<T: FSerializable>(pub Vec<T>);
impl<T: FSerializable> VSerializable for LargeVector<T> {
    fn ser(&self) -> Vec<u8> {
        let items = self.0.len();
        let length = items * T::size_bytes();
        let mut ret = Vec::with_capacity(LENGTH_BYTES + length);
        // for LargeVector, the length tag is the number of elements in the vector, not the length of the serialized data
        let len: LengthU = self.0.len().try_into().expect("Length conversion failed");
        ret.extend_from_slice(&len.to_be_bytes());
        for item in &self.0 {
            item.ser_into(&mut ret);
        }

        ret
    }
}

impl<T: FSerializable + FDeserializable> VDeserializable for LargeVector<T> {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let len_bytes: [u8; LENGTH_BYTES] = buffer[0..LENGTH_BYTES].try_into()?;
        // for LargeVector, the length tag is the number of elements in the vector, not the length of the serialized data
        let len: usize = LengthU::from_be_bytes(len_bytes)
            .try_into()
            .expect("Length conversion failed");

        let bytes = &buffer[LENGTH_BYTES..];
        let each = bytes.len() / len;

        if each != T::size_bytes() {
            return Err(Error::DeserializationError(
                "Unexpected chunk size for LargeVector".to_string(),
            ));
        }

        let chunks = bytes.chunks_exact(each);
        let chunks = chunks.map(|e| T::deser_f(e));
        let ret: Result<Vec<T>, Error> = chunks.collect();
        ret.map(|v| LargeVector(v))
    }
}

// Convert a struct to and from its equivalent tuple
pub trait TFTuple: Sized {
    type TupleRef<'a>: VSerializable
    where
        Self: 'a;
    type Tuple: VDeserializable;

    fn as_tuple<'a>(&'a self) -> Self::TupleRef<'a>;
    fn from_tuple(tuple: Self::Tuple) -> Result<Self, Error>;
}

impl VSerializable for String {
    fn ser(&self) -> Vec<u8> {
        let bytes = self.as_bytes();
        let len: LengthU = bytes.len().try_into().expect("Length conversion failed");
        let mut ret = len.to_be_bytes().to_vec();
        ret.extend_from_slice(bytes);

        ret
    }
}

impl VDeserializable for String {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let len_bytes: [u8; LENGTH_BYTES] = buffer[0..LENGTH_BYTES].try_into()?;
        let len: usize = LengthU::from_be_bytes(len_bytes)
            .try_into()
            .expect("Length conversion failed");

        let bytes = &buffer[LENGTH_BYTES..LENGTH_BYTES + len];

        let string = String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::DeserializationError("Failed to deserialize String".into()))?;
        Ok(string)
    }
}

#[crate::warning("Remove this, only temporary for strand challenge input to work")]
impl VSerializable for u8 {
    fn ser(&self) -> Vec<u8> {
        vec![*self]
    }
}

impl<A: VSerializable> VSerializable for (A,) {
    fn ser(&self) -> Vec<u8> {
        let head = self.0.ser();
        let len: LengthU = head.len().try_into().expect("Length conversion failed");
        let mut bytes = len.to_be_bytes().to_vec();
        bytes.extend(head);
        bytes
    }
}

impl<A: VDeserializable> VDeserializable for (A,) {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let len_bytes: [u8; LENGTH_BYTES] = buffer[0..LENGTH_BYTES].try_into()?;
        let len: usize = LengthU::from_be_bytes(len_bytes)
            .try_into()
            .expect("Length conversion failed");
        let bytes = &buffer[LENGTH_BYTES..];
        if bytes.len() != len {
            return Err(Error::DeserializationError(
                "Unexpected byte length for (A,)".into(),
            ));
        }

        let a = A::deser(bytes)?;

        Ok((a,))
    }
}

impl<A: VSerializable, B: VSerializable> VSerializable for (A, B) {
    fn ser(&self) -> Vec<u8> {
        let head = self.0.ser();
        let len: LengthU = head.len().try_into().expect("Length conversion failed");
        let mut bytes = len.to_be_bytes().to_vec();
        bytes.extend(head);
        let tail = self.1.ser();
        bytes.extend(tail);
        bytes
    }
}

impl<A: VDeserializable, B: VDeserializable> VDeserializable for (A, B) {
    fn deser(buffer: &[u8]) -> Result<Self, Error> {
        let len_bytes: [u8; LENGTH_BYTES] = buffer[0..LENGTH_BYTES].try_into()?;
        let len: usize = LengthU::from_be_bytes(len_bytes)
            .try_into()
            .expect("Length conversion failed");
        let a_bytes = &buffer[LENGTH_BYTES..LENGTH_BYTES + len];
        let b_bytes = &buffer[LENGTH_BYTES + len..];
        let a = A::deser(a_bytes)?;
        let b = B::deser(b_bytes)?;
        Ok((a, b))
    }
}

macro_rules! generate_tuple_impl {
    // `$head` is the first generic type (e.g., A).
    // `$($tail_tys)` is a sequence of the remaining generic types (e.g., B, C, D).
    // `$($tail_indices)` is a sequence of the tuple indices for the tail (e.g., 1, 2, 3).
    // `$($tail_access)` is a sequence of the tuple indices to access the deserialized tail (e.g., 0, 1, 2).
    ($head_ty:ident, $($tail_tys:ident),+; $($tail_indices:tt),+; $($tail_access:tt),+) => {

        // Implementation for VSerializable
        impl<$head_ty: VSerializable, $($tail_tys: VSerializable),+> VSerializable for ($head_ty, $($tail_tys),+) {
            fn ser(&self) -> Vec<u8> {
                let head = self.0.ser();
                let len: LengthU = head.len().try_into().expect("Length conversion failed");
                let mut bytes = len.to_be_bytes().to_vec();
                bytes.extend(head);
                // Recursively serialize the rest of the tuple.
                // The `( $( &self.$tail_indices ),+ )` part constructs the tail tuple, e.g., (&self.1, &self.2).
                let tail = ( $( &self.$tail_indices ),+ ).ser();
                bytes.extend(tail);
                bytes
            }
        }

        // Implementation for VDeserializable
        impl<$head_ty: VDeserializable, $($tail_tys: VDeserializable),+> VDeserializable for ($head_ty, $($tail_tys),+) {
            fn deser(buffer: &[u8]) -> Result<Self, Error> {
                let len_bytes: [u8; LENGTH_BYTES] = buffer[0..LENGTH_BYTES].try_into()?;
                let len: usize = LengthU::from_be_bytes(len_bytes)
                    .try_into()
                    .expect("Length conversion failed");

                let head_bytes = &buffer[LENGTH_BYTES..LENGTH_BYTES + len];
                let tail_bytes = &buffer[LENGTH_BYTES + len..];

                let head = $head_ty::deser(&head_bytes.to_vec())?;
                // Recursively deserialize the rest of the tuple.
                // The `<( $($tail_tys),+ )>` part constructs the tail's type, e.g., <(B, C)>.
                let tail = <( $($tail_tys),+ )>::deser(&tail_bytes.to_vec())?;

                // The `(head, $( tail.$tail_access ),+ )` part reconstructs the final tuple, e.g., (head, tail.0, tail.1).
                Ok((head, $( tail.$tail_access ),+))
            }
        }
    };
}

macro_rules! impl_vser_for_tuples {
    () => {

        generate_tuple_impl!(A, B, C; 1, 2; 0, 1);

        generate_tuple_impl!(A, B, C, D; 1, 2, 3; 0, 1, 2);

        generate_tuple_impl!(A, B, C, D, E; 1, 2, 3, 4; 0, 1, 2, 3);

        generate_tuple_impl!(A, B, C, D, E, F; 1, 2, 3, 4, 5; 0, 1, 2, 3, 4);

        generate_tuple_impl!(A, B, C, D, E, F, G; 1, 2, 3, 4, 5, 6; 0, 1, 2, 3, 4, 5);
    };
}

impl_vser_for_tuples!();
