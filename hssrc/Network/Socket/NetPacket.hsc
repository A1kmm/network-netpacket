{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, ForeignFunctionInterface #-}
module Network.Socket.NetPacket
where
  
import Network.Socket
import Foreign.C.Types
import Foreign.C.Error
import Foreign.C.String
import Foreign.Storable
import Foreign.Ptr
import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Word
import Control.Applicative
import Network.Socket.InterfaceRequest
import Foreign.Storable.Asymmetric
import Network.Socket.IOCtl
import GHC.Conc (threadWaitWrite, threadWaitRead)
import Data.Maybe
import Foreign.Marshal

foreign import ccall "sendto" c_sendto_ll :: CInt -> CString -> CSize -> CInt -> Ptr SockAddrLL -> CSize -> IO CSize
foreign import ccall "recvfrom" c_recvfrom_ll :: CInt -> CString -> CSize -> CInt -> Ptr SockAddrLL -> CSize -> IO CSize

#include <netpacket/packet.h>

data PktType = PktType { unPktType :: Word8 }
#enum PktType, PktType, packetHost = PACKET_HOST, packetBroadcast = PACKET_BROADCAST, packetMulticast = PACKET_MULTICAST, packetOtherhost = PACKET_OTHERHOST, packetOutgoing = PACKET_OUTGOING, packetLoopback = PACKET_LOOPBACK, packetFastroute = PACKET_FASTROUTE

newtype LLProtocol = LLProtocol Word16
lLProtocolIPv4 = LLProtocol 0x0800
lLProtocolIPv6 = LLProtocol 0x86DD

newtype HardwareType = HardwareType Word16
hwTypeEther = HardwareType 0x1

-- | Hardware address
data HWAddr = HWAddr BS.ByteString

newtype IFIndex = IFIndex Int
data SockAddrLL = SockAddrLL LLProtocol IFIndex HardwareType PktType HWAddr

instance Storable LLProtocol where
  sizeOf _ = sizeOf (undefined :: Word16)
  alignment _ = alignment (undefined :: Word16)
  peek p = liftM LLProtocol $ peek (castPtr p)
  poke p (LLProtocol v) = poke (castPtr p) v

instance Storable HardwareType where
  sizeOf _ = sizeOf (undefined :: Word16)
  alignment _ = alignment (undefined :: Word16)
  peek p = liftM HardwareType $ peek (castPtr p)
  poke p (HardwareType v) = poke (castPtr p) v

instance Storable PktType where
  sizeOf _ = sizeOf (undefined :: Word8)
  alignment _ = alignment (undefined :: Word8)
  peek p = liftM PktType (peek (castPtr p))
  poke p v = poke ((castPtr p) :: Ptr Word8) (unPktType v)

instance Storable IFIndex where
  sizeOf _ = sizeOf (undefined :: Word32)
  alignment _ = alignment (undefined :: Word32)
  peek p = liftM IFIndex $ peek (castPtr p)
  poke p (IFIndex v) = poke (castPtr p) v

instance Storable SockAddrLL where
  sizeOf _ = #size struct sockaddr_ll
  alignment _ = alignment (undefined :: CInt)
  peek p = SockAddrLL <$>
             (peek $ (#ptr struct sockaddr_ll, sll_protocol) p) <*>
             (peek $ (#ptr struct sockaddr_ll, sll_ifindex) p) <*>
             (peek $ (#ptr struct sockaddr_ll, sll_hatype) p) <*>
             (peek $ (#ptr struct sockaddr_ll, sll_pkttype) p) <*>
             (HWAddr <$> ((((,) ((#ptr struct sockaddr_ll, sll_addr) p)) <$>
                           liftM fromIntegral (((#peek struct sockaddr_ll, sll_halen) p) :: IO Word8)) >>= BS.packCStringLen))
  poke p (SockAddrLL proto ifi hatype pkttype (HWAddr hwaddr)) = do
    poke ((#ptr struct sockaddr_ll, sll_protocol) p) proto
    poke ((#ptr struct sockaddr_ll, sll_ifindex) p) ifi
    poke ((#ptr struct sockaddr_ll, sll_hatype) p) hatype
    poke ((#ptr struct sockaddr_ll, sll_pkttype) p) pkttype
    BS.unsafeUseAsCStringLen hwaddr $ \(chwaddr, l) -> do
      poke ((#ptr struct sockaddr_ll, sll_halen) p) ((fromIntegral l) :: Word8)
      let aptr = (#ptr struct sockaddr_ll, sll_addr) p
      forM_ [0..7] $ \idx -> do
        v <- if idx < l then peekByteOff chwaddr idx
                        else return 0
        pokeByteOff aptr idx (v :: Word8)

data GetIndexForName = GetIndexForName
instance IOControl GetIndexForName (DifferentPeekPoke (InterfaceRequest NoData) (InterfaceRequest CInt)) where
  ioctlReq _ = 0x8933

getInterfaceIndex :: Socket -> String -> IO IFIndex
getInterfaceIndex s n = do
  liftA (IFIndex . fromIntegral . irValue . getPeek) $ ioctlsocket s GetIndexForName (PokeIn (InterfaceRequest n NoData))

sendToLL :: Socket -> BS.ByteString -> SockAddrLL -> IO Int
sendToLL (MkSocket fd _ _ _ _) bs addr = liftM fromIntegral $
  flip (throwErrnoIfMinus1RetryMayBlock
        "sendToLL")
    (threadWaitWrite (fromIntegral fd)) $ do
      BS.unsafeUseAsCStringLen bs $ \(cs, l) ->
        with addr $ \paddr ->
          c_sendto_ll fd cs (fromIntegral l) 0 paddr (fromIntegral $ sizeOf addr)

recvFromLL :: Socket -> Int -> SockAddrLL -> IO BS.ByteString
recvFromLL (MkSocket fd _ _ _ _) bufl addr = liftM fromJust $
  flip (throwErrnoIfRetryMayBlock
        (==Nothing)
        "recvFromLL")
    (threadWaitRead (fromIntegral fd)) $ do
      v <- mallocBytes bufl
      ret <- with addr $ \paddr ->
        c_recvfrom_ll fd v (fromIntegral bufl) 0 paddr (fromIntegral $ sizeOf addr)
      if ret == -1
        then free v >> return Nothing
        else do
          liftM Just (BS.unsafePackCStringFinalizer (castPtr v) (fromIntegral ret) (free v))
