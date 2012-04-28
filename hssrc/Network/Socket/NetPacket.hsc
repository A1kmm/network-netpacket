{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, ForeignFunctionInterface #-}
-- | A module for working with the NetPacket interface, giving the ability to send and
-- | receive raw low-level network packets such as Ethernet frames.
-- | Example:
-- |   import Network.Socket
-- |   import Network.Socket.NetPacket
-- |   main = do
-- |     s <- socket AF_PACKET Raw ethProtocolAll
-- |     p@(addr, dg) <- recvFromLL s 4096
-- |     print ("Received packet: " ++ show p)
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

-- | Low-level sendto call. Normally, this would not be used, as sendToLL provides a
-- | more convenient interface.
foreign import ccall "sendto" c_sendto_ll :: CInt -> CString -> CSize -> CInt -> Ptr SockAddrLL -> CSize -> IO CSize

-- | Low-level recvfrom call. Normally, this would not be used, as recvFromLL provides
-- | a more convenient interface.
foreign import ccall "recvfrom" c_recvfrom_ll :: CInt -> CString -> CSize -> CInt -> Ptr SockAddrLL -> Ptr CSize -> IO CSize

-- | Low-level setsockopt operation. Normally, it will be more convenient to use
-- | setPacketOption instead.
foreign import ccall "setsockopt" c_setsockopt_ll :: CInt -> CInt -> CInt -> Ptr () -> CSize -> IO CInt

-- | Low-level bind operation. Normally, this would not be used, as bindLL provides a
-- | more convenient interface.
foreign import ccall "bind" c_bind_ll :: CInt -> Ptr SockAddrLL -> CSize -> IO CInt

#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>

-- | Ethernet protocol numbers, for use with socket
#enum ProtocolNumber,, ethProtocolIPv4 = htons(ETH_P_IP), ethProtocolIPv6 = htons(ETH_P_IPV6), ethProtocolAll = htons(ETH_P_ALL)

-- | Represents a type of packet
data PktType = PktType { unPktType :: Word8 } deriving (Eq, Ord, Show)
#enum PktType, PktType, packetHost = PACKET_HOST, packetBroadcast = PACKET_BROADCAST, packetMulticast = PACKET_MULTICAST, packetOtherhost = PACKET_OTHERHOST, packetOutgoing = PACKET_OUTGOING, packetLoopback = PACKET_LOOPBACK, packetFastroute = PACKET_FASTROUTE

-- | The address family of a packet socket.
#enum CInt,, afPacket = AF_PACKET

-- | Represents a low-level protocol appearing in an address.
newtype LLProtocol = LLProtocol Word16 deriving (Eq, Ord, Show)
#enum LLProtocol, LLProtocol, lLProtocolIPv4 = htons(ETH_P_IP), lLProtocolIPv6 = htons(ETH_P_IPV6), lLProtocolAll = htons(ETH_P_ALL)

-- | Represents a hardware type appearing in an address.
newtype HardwareType = HardwareType Word16 deriving (Eq, Ord, Show)
-- | Represents the Ethernet hardware type
hwTypeEther = HardwareType 0x1

-- | Hardware address
data HWAddr = HWAddr BS.ByteString deriving (Eq, Ord, Show)

noHWAddr = HWAddr BS.empty

newtype IFIndex = IFIndex Int deriving (Eq, Ord, Show)
data SockAddrLL = SockAddrLL LLProtocol IFIndex HardwareType PktType HWAddr deriving (Eq, Ord, Show)

defaultSockAddrLL = SockAddrLL lLProtocolIPv4 (IFIndex 0) hwTypeEther packetHost (HWAddr $ BS.pack [])

#enum CInt,, solPacket = SOL_PACKET
newtype PacketSocketOption = PacketSocketOption Int deriving (Eq, Ord, Show)
#enum PacketSocketOption, PacketSocketOption, packetAddMembership = PACKET_ADD_MEMBERSHIP, packetDropMembership = PACKET_DROP_MEMBERSHIP, packetRecvOutput = PACKET_RECV_OUTPUT, packetRXRing = PACKET_RX_RING, packetStatistics = PACKET_STATISTICS

newtype PacketMReqType = PacketMReqType Word16 deriving (Eq, Ord, Show)
#enum PacketMReqType, PacketMReqType, mrMulticast = PACKET_MR_MULTICAST, mrPromisc = PACKET_MR_PROMISC, mrAllMulti = PACKET_MR_ALLMULTI

data PacketMReq = PacketMReq IFIndex PacketMReqType HWAddr

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
  peek p = liftM (IFIndex . fromIntegral) $ peek ((castPtr p) :: Ptr CInt)
  poke p (IFIndex v) = poke ((castPtr p) :: Ptr CInt) (fromIntegral v)

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
    (#poke struct sockaddr_ll, sll_family) p afPacket
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

instance Storable PacketSocketOption where
  sizeOf _ = sizeOf (undefined :: CInt)
  alignment _ = alignment (undefined :: CInt)
  peek p = liftM (PacketSocketOption . fromIntegral) $ (peek (castPtr p) :: IO CInt)
  poke p (PacketSocketOption v) = poke (castPtr p :: Ptr CInt) (fromIntegral v)

instance Storable PacketMReqType where
  sizeOf _ = sizeOf (undefined :: Word16)
  alignment _ = alignment (undefined :: Word16)
  peek p = liftM (PacketMReqType . fromIntegral) $ (peek (castPtr p) :: IO Word16)
  poke p (PacketMReqType v) = poke (castPtr p :: Ptr Word16) (fromIntegral v)

instance Storable PacketMReq where
  sizeOf _ = #size struct packet_mreq
  alignment _ = alignment (undefined :: CInt)
  peek p = PacketMReq <$> (peek $ (#ptr struct packet_mreq, mr_ifindex) p) <*>
                          (peek $ (#ptr struct packet_mreq, mr_type) p) <*>
                          (HWAddr <$> ((((,) ((#ptr struct packet_mreq, mr_address) p)) <$>
                           liftM fromIntegral (((#peek struct packet_mreq, mr_address) p) :: IO Word16)) >>= BS.packCStringLen))
  poke p (PacketMReq ii mt (HWAddr a)) = do
    poke ((#ptr struct packet_mreq, mr_ifindex) p) ii
    poke ((#ptr struct packet_mreq, mr_type) p) mt
    BS.unsafeUseAsCStringLen a $ \(chwaddr, l) -> do
      poke ((#ptr struct packet_mreq, mr_alen) p) ((fromIntegral l) :: Word16)
      let aptr = (#ptr struct packet_mreq, mr_address) p
      forM_ [0..7] $ \idx -> do
        v <- if idx < l then peekByteOff chwaddr idx
                        else return 0
        pokeByteOff aptr idx (v :: Word8)

data GetIndexForName = GetIndexForName
instance IOControl GetIndexForName (DifferentPeekPoke (InterfaceRequest NoData) (InterfaceRequest CInt)) where
  ioctlReq _ = 0x8933

-- | Gets the index for a named interface, for use with SockAddrLL
getInterfaceIndex :: Socket -> String -> IO IFIndex
getInterfaceIndex s n = do
  liftA (IFIndex . fromIntegral . irValue . getPeek) $ ioctlsocket s GetIndexForName (PokeIn (InterfaceRequest n NoData))

-- | Sends a packet to a particular low-level socket address.
sendToLL :: Socket -> BS.ByteString -> SockAddrLL -> IO Int
sendToLL (MkSocket fd _ _ _ _) bs addr = liftM fromIntegral $
  flip (throwErrnoIfMinus1RetryMayBlock
        "sendToLL")
    (threadWaitWrite (fromIntegral fd)) $
      BS.unsafeUseAsCStringLen bs $ \(cs, l) ->
        with addr $ \paddr ->
            c_sendto_ll fd cs (fromIntegral l) 0 paddr (fromIntegral $ sizeOf addr)

-- | Receives a packet from a socket, returning the address of the packet.
recvFromLL :: Socket -> Int -> IO (SockAddrLL, BS.ByteString)
recvFromLL (MkSocket fd _ _ _ _) bufl = liftM fromJust $
  flip (throwErrnoIfRetryMayBlock
        (==Nothing)
        "recvFromLL")
    (threadWaitRead (fromIntegral fd)) $ do
      v <- mallocBytes bufl
      with defaultSockAddrLL $ \paddr ->
        with ((fromIntegral $ sizeOf defaultSockAddrLL) :: CSize) $ \psize -> do
          ret <- c_recvfrom_ll fd v (fromIntegral bufl) 0 paddr psize
          if ret == -1
            then free v >> return Nothing
            else do
              liftM Just $ (,) <$> peek paddr <*> BS.unsafePackCStringFinalizer (castPtr v) (fromIntegral ret) (free v)

-- | Sets an option on a packet socket. This can be used to control the receipt of multicast packets
setPacketOption :: Socket -> PacketSocketOption -> PacketMReq -> IO ()
setPacketOption (MkSocket fd _ _ _ _) (PacketSocketOption pso) req = do
  throwErrnoIfMinus1 "setPacketOption" $  
    with req $ \preq ->
      c_setsockopt_ll fd solPacket (fromIntegral pso) (castPtr preq) (fromIntegral $ sizeOf req)
  return ()

-- | Binds a packet socket to an address. This is not essential, but acts as a filter on received packets.
bindLL :: Socket -> SockAddrLL -> IO ()
bindLL (MkSocket fd _ _ _ _) addr = do
  throwErrnoIfMinus1 "bindLL" $ with addr $ \paddr ->
    c_bind_ll fd paddr (fromIntegral $ sizeOf addr)
  return ()
