(in-package :snif)

(defparameter *eth-protocols*
  (list
   (defconstant ETH_P_LOOP       #x0060 "Ethernet Loopback packet")
   (defconstant ETH_P_PUP        #x0200 "Xerox PUP packet")
   (defconstant ETH_P_PUPAT      #x0201 "Xerox PUP Addr Trans packet")
   (defconstant ETH_P_IP         #x0800 "Internet Protocol packet")
   (defconstant ETH_P_X25        #x0805 "CCITT X.25")
   (defconstant ETH_P_ARP        #x0806 "Address Resolution packet")
   (defconstant ETH_P_BPQ        #x08FF "G8BPQ AX.25 Ethernet Packet [ NOT AN OFFICIALLY REGISTERED ID ]")
   (defconstant ETH_P_IEEEPUP    #x0a00 "Xerox IEEE802.3 PUP packet ")
   (defconstant ETH_P_IEEEPUPAT  #x0a01 "Xerox IEEE802.3 PUP Addr Trans packet")
   (defconstant ETH_P_DEC        #x6000 "DEC Assigned proto")
   (defconstant ETH_P_DNA_DL     #x6001 "DEC DNA Dump/Load")
   (defconstant ETH_P_DNA_RC     #x6002 "DEC DNA Remote Console")
   (defconstant ETH_P_DNA_RT     #x6003 "DEC DNA Routing")
   (defconstant ETH_P_LAT        #x6004 "DEC LAT")
   (defconstant ETH_P_DIAG       #x6005 "DEC Diagnostics")
   (defconstant ETH_P_CUST       #x6006 "DEC Customer use")
   (defconstant ETH_P_SCA        #x6007 "DEC Systems Comms Arch")
   (defconstant ETH_P_TEB        #x6558 "Trans Ether Bridging")
   (defconstant ETH_P_RARP       #x8035 "Reverse Addr Res packet")
   (defconstant ETH_P_ATALK      #x809B "Appletalk DDP")
   (defconstant ETH_P_AARP       #x80F3 "Appletalk AARP")
   (defconstant ETH_P_8021Q      #x8100 "802.1Q VLAN Extended Header")
   (defconstant ETH_P_IPX        #x8137 "IPX over DIX")
   (defconstant ETH_P_IPV6       #x86DD "IPv6 over bluebook")
   (defconstant ETH_P_PAUSE      #x8808 "IEEE Pause frames. See 802.3 31B")
   (defconstant ETH_P_SLOW       #x8809 "Slow Protocol. See 802.3ad 43B")
   (defconstant ETH_P_WCCP       #x883E "Web-cache coordination protocol")
   (defconstant ETH_P_PPP_DISC   #x8863 "PPPoE discovery messages")
   (defconstant ETH_P_PPP_SES    #x8864 "PPPoE session messages")
   (defconstant ETH_P_MPLS_UC    #x8847 "MPLS Unicast traffic")
   (defconstant ETH_P_MPLS_MC    #x8848 "MPLS Multicast traffic")
   (defconstant ETH_P_ATMMPOA    #x884c "MultiProtocol Over ATM")
   (defconstant ETH_P_ATMFATE    #x8884 "Frame-based ATM Transport")
   (defconstant ETH_P_PAE        #x888E "Port Access Entity (IEEE 802.1X)")
   (defconstant ETH_P_AOE        #x88A2 "ATA over Ethernet")
   (defconstant ETH_P_TIPC       #x88CA "TIPC")
   (defconstant ETH_P_1588       #x88F7 "IEEE 1588 Timesync")
   (defconstant ETH_P_FCOE       #x8906 "Fibre Channel over Ethernet")
   (defconstant ETH_P_FIP        #x8914 "FCoE Initialization Protocol")
   (defconstant ETH_P_EDSA       #xDADA "Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]")
   (defconstant ETH_P_802_3      #x0001 "Dummy type for 802.3 frames")
   (defconstant ETH_P_AX25       #x0002 "Dummy protocol id for AX.25")
   (defconstant ETH_P_ALL        #x0003 "Every packet (be careful!!!)")
   (defconstant ETH_P_802_2      #x0004 "802.2 frames")
   (defconstant ETH_P_SNAP       #x0005 "Internal only")
   (defconstant ETH_P_DDCMP      #x0006 "DEC DDCMP: Internal only")
   (defconstant ETH_P_WAN_PPP    #x0007 "Dummy type for WAN PPP frames")
   (defconstant ETH_P_PPP_MP     #x0008 "Dummy type for PPP MP frames")
   (defconstant ETH_P_LOCALTALK  #x0009 "Localtalk pseudo type")
   (defconstant ETH_P_CAN        #x000C "Controller Area Network")
   (defconstant ETH_P_PPPTALK    #x0010 "Dummy type for Atalk over PPP")
   (defconstant ETH_P_TR_802_2   #x0011 "802.2 frames")
   (defconstant ETH_P_MOBITEX    #x0015 "Mobitex (kaz@cafe.net)")
   (defconstant ETH_P_CONTROL    #x0016 "Card specific control frames")
   (defconstant ETH_P_IRDA       #x0017 "Linux-IrDA")
   (defconstant ETH_P_ECONET     #x0018 "Acorn Econet")
   (defconstant ETH_P_HDLC       #x0019 "HDLC frames")
   (defconstant ETH_P_ARCNET     #x001A "1A for ArcNet :-)")
   (defconstant ETH_P_DSA        #x001B "Distributed Switch Arch.")
   (defconstant ETH_P_TRAILER    #x001C "Trailer switch tagging")
   (defconstant ETH_P_PHONET     #x00F5 "Nokia Phonet frames")
   (defconstant ETH_P_IEEE802154 #x00F6 "IEEE802.15.4 frame")))

(defparameter *name->protocol*
  (let ((map (make-hash-table :test #'eq)))
    (dolist (sym *eth-protocols* map)
      (let ((key (intern (subseq (symbol-name sym) 6) :keyword)))
        (setf (gethash key map) (symbol-value sym))))))

(defparameter *value->protocol-name*
  (let ((map (make-hash-table)))
    (dolist (sym *eth-protocols* map)
      (let ((key (intern (subseq (symbol-name sym) 6) :keyword))
            (val (symbol-value sym)))
        (setf (gethash val map) key)))))

(defun find-protocol-by-name (name)
  (gethash name *name->protocol*))

(defun find-protocol-by-value (value)
  (gethash value *value->protocol-name* :unknown))

(defun list-all-protocols ()
  (flet ((name (sym)
           (intern (subseq (symbol-name sym) 6) :keyword)))
    (mapcar (lambda (s) (list (name s) (documentation s 'variable)))
            *eth-protocols*)))
