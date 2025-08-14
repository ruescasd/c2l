use crate::utils::serialization::TFTuple;
use crate::utils::Error;

pub trait FSer: FSerializable + FDeserializable {}
impl<T: FSerializable + FDeserializable> FSer for T {}

pub trait FSerializable {
    fn size_bytes() -> usize;
    fn ser_into(&self, buffer: &mut Vec<u8>);
    fn ser_f(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(Self::size_bytes());
        self.ser_into(&mut buffer);

        buffer
    }
}

pub trait FDeserializable: Sized {
    fn deser_f(buffer: &[u8]) -> Result<Self, Error>;
}

// FSerializable implementation for tuple compatible structs
//
// A type T is FSerializable if
// 1) it has a tuple conversion
// 2) its tuple serialization has a fixed size
impl<T> FSerializable for T
where
    T: TFTuple,
    // We use TupleRef instead of Tuple here because serialization
    // code is implemented on the tuple of _references_
    // The Tuple type is used for deserialization as in Tuple::deser...
    for<'a> T::TupleRef<'a>: FSerializable,
{
    fn size_bytes() -> usize {
        T::TupleRef::size_bytes()
    }
    fn ser_into(&self, buffer: &mut Vec<u8>) {
        self.as_tuple().ser_into(buffer);
    }
}

// FDeserializable implementation for tuple compatible structs
//
// A type T is FDeserializable if
// 1) it has a tuple conversion
// 2) its tuple serialization has a fixed size
// 3) its tuple deserialization has fixed size
impl<T> FDeserializable for T
where
    T: TFTuple,
    for<'a> T::TupleRef<'a>: FSerializable,
    T::Tuple: FDeserializable,
{
    fn deser_f(buffer: &[u8]) -> Result<T, Error> {
        let expected = T::TupleRef::size_bytes();
        if buffer.len() != expected {
            return Err(Error::DeserializationError(
                "Unexpected number of bytes for struct tuple".to_string(),
            ));
        }
        let tuple = T::Tuple::deser_f(buffer)?;
        T::from_tuple(tuple)
    }
}

impl<T: FSerializable, const N: usize> FSerializable for [T; N] {
    fn size_bytes() -> usize {
        N * T::size_bytes()
    }

    fn ser_into(&self, buffer: &mut Vec<u8>) {
        for v in self {
            v.ser_into(buffer);
        }
    }
}

impl<T: FSerializable + FDeserializable, const N: usize> FDeserializable for [T; N] {
    fn deser_f(buffer: &[u8]) -> Result<Self, Error> {
        let expected = T::size_bytes() * N;
        if buffer.len() != expected {
            return Err(Error::DeserializationError(
                "Unexpected byte size for [T; N]".to_string(),
            ));
        }

        let each = T::size_bytes();
        let chunks = buffer.chunks_exact(each);
        let chunks = chunks.map(|e| T::deser_f(e));

        let ts: Vec<T> = chunks.collect::<Result<Vec<T>, Error>>()?;
        let ret: Result<[T; N], Error> = ts.try_into().map_err(|_| {
            Error::DeserializationError("Failed converting Vec<T> to [T; N]".to_string())
        });

        ret
    }
}

impl<A: FSerializable> FSerializable for (&A,) {
    fn size_bytes() -> usize {
        A::size_bytes()
    }

    fn ser_into(&self, buffer: &mut Vec<u8>) {
        self.0.ser_into(buffer);
    }
}

impl<A: FSerializable, B: FSerializable> FSerializable for (&A, &B) {
    fn size_bytes() -> usize {
        A::size_bytes() + B::size_bytes()
    }

    fn ser_into(&self, buffer: &mut Vec<u8>) {
        // Serialize head
        self.0.ser_into(buffer);
        // Serialize the tail
        self.1.ser_into(buffer);
    }
}

macro_rules! generate_fserializable_tuple_impl {
    // $head_ty: The first generic type (e.g., A)
    // $($tail_tys): The rest of the generic types (e.g., B, C, D)
    // $($tail_indices): The tuple indices for the tail (e.g., 1, 2, 3)
    ($head_ty:ident, $($tail_tys:ident),+; $($tail_indices:tt),+) => {
        impl<$head_ty: FSerializable, $($tail_tys: FSerializable),+> FSerializable for (&$head_ty, $(&$tail_tys),+) {

            /// size = (length_of_head + size_of_head) + size_of_tail_tuple
            fn size_bytes() -> usize {
                // LENGTH_BYTES + $head_ty::size_bytes() + <( $(&$tail_tys),+ )>::size_bytes()
                $head_ty::size_bytes() + <( $(&$tail_tys),+ )>::size_bytes()
            }

            fn ser_into(&self, buffer: &mut Vec<u8>) {
                // Serialize head
                self.0.ser_into(buffer);
                // This constructs the tail tuple, e.g., (&self.1, &self.2), and calls ser_into on it.
                let tail = ( $( self.$tail_indices ),+ );
                tail.ser_into(buffer);
            }
        }
    };
}

macro_rules! impl_fser_for_tuples {
    () => {

        generate_fserializable_tuple_impl!(A, B, C; 1, 2);

        generate_fserializable_tuple_impl!(A, B, C, D; 1, 2, 3);

        generate_fserializable_tuple_impl!(A, B, C, D, E; 1, 2, 3, 4);

        generate_fserializable_tuple_impl!(A, B, C, D, E, F; 1, 2, 3, 4, 5);

        generate_fserializable_tuple_impl!(A, B, C, D, E, F, G; 1, 2, 3, 4, 5, 6);
    };
}

impl_fser_for_tuples!();

impl<A: FSerializable + FDeserializable> FDeserializable for (A,) {
    fn deser_f(buffer: &[u8]) -> Result<Self, Error> {
        let length_a = A::size_bytes();
        if buffer.len() != length_a {
            return Err(Error::DeserializationError(
                "Unexpected byte length for (A,)".into(),
            ));
        }
        let a = A::deser_f(buffer)?;
        Ok((a,))
    }
}

impl<A: FSerializable + FDeserializable, B: FSerializable + FDeserializable> FDeserializable
    for (A, B)
{
    fn deser_f(buffer: &[u8]) -> Result<Self, Error> {
        let length_a = A::size_bytes();
        let a_bytes = &buffer[0..length_a];
        let b_bytes = &buffer[length_a..];
        let a = A::deser_f(a_bytes)?;
        let b = B::deser_f(b_bytes)?;
        Ok((a, b))
    }
}

macro_rules! generate_fdeserializable_tuple_impl {
    // $head_ty: The first generic type (e.g., A)
    // $($tail_tys): The rest of the generic types (e.g., B, C, D)
    // $($tail_access): The indices to deconstruct the deserialized tail tuple (e.g., 0, 1, 2)
    ($head_ty:ident, $($tail_tys:ident),+; $($tail_access:tt),+) => {
        impl<
            $head_ty: FSerializable + FDeserializable,
            $($tail_tys: FSerializable + FDeserializable),+
        > FDeserializable for ($head_ty, $($tail_tys),+) {
            fn deser_f(buffer: &[u8]) -> Result<Self, Error> {
                // Determine the slice for the head element using its fixed size.
                let head_len = $head_ty::size_bytes();
                let head_bytes = &buffer[0..head_len];
                let tail_bytes = &buffer[head_len..];

                // Deserialize the head and the tail recursively.
                let head = $head_ty::deser_f(head_bytes)?;
                // The <(...)> syntax specifies the type for the recursive call.
                let tail = <( $($tail_tys),+ )>::deser_f(tail_bytes)?;

                // Reconstruct the final tuple from the deserialized parts.
                // The `tail.$tail_access` part expands to tail.0, tail.1, etc.
                Ok((head, $( tail.$tail_access ),+))
            }
        }
    };
}

macro_rules! impl_fdeserializable_for_tuples {
    () => {

        generate_fdeserializable_tuple_impl!(A, B, C; 0, 1);

        generate_fdeserializable_tuple_impl!(A, B, C, D; 0, 1, 2);

        generate_fdeserializable_tuple_impl!(A, B, C, D, E; 0, 1, 2, 3);

        generate_fdeserializable_tuple_impl!(A, B, C, D, E, F; 0, 1, 2, 3, 4);

        generate_fdeserializable_tuple_impl!(A, B, C, D, E, F, G; 0, 1, 2, 3, 4, 5);
    };
}

impl_fdeserializable_for_tuples!();
