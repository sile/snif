(in-package :snif)
;; http://www.fenix.ne.jp/~thomas/memo/linux_raw_packet/
;; http://linuxjm.sourceforge.jp/html/LDP_man-pages/man7/packet.7.html

(defun %make-packet-fd (protocol)
  (let ((fd (socket +PF_PACKET+ +SOCK_RAW+ (to-network-order protocol 2))))
    (when (/= fd -1)
      fd)))

(defmacro with-ifreq ((var interface-name) &body body)
  `(with-zeroset-alien (,var ifreq)
     (strncpy (ifreq.name ,var) ,interface-name +IFNAMSIZ+)
     ,@body))

(defun interface-index (fd interface-name)
  (declare #.*muffle-compiler-note*)
  (with-ifreq (ifr interface-name)
    (when (sb-unix:unix-ioctl fd +SIOCGIFINDEX+ (alien-sap ifr))
      (ifreq.index ifr))))

(defun promisc-mode (interface-name)
  (declare #.*muffle-compiler-note*)
  (named.when (fd (%make-packet-fd ETH_P_ALL))
    (with-ifreq (ifr interface-name)
      (when (sb-unix:unix-ioctl fd +SIOCGIFFLAGS+ (alien-sap ifr))
        (return-from promisc-mode 
                     (values (logtest +IFF_PROMISC+ (ifreq.flags ifr)) t)))))
  (values nil nil))

(defun set-promisc-mode (interface-name enable)
  (declare #.*muffle-compiler-note*)
  (named.when (fd (%make-packet-fd ETH_P_ALL))
    (with-ifreq (ifr interface-name)
      (values
       (and (sb-unix:unix-ioctl fd +SIOCGIFFLAGS+ (alien-sap ifr))
            (setf (ifreq.flags ifr)
                  (boole (if enable boole-ior boole-andc1) 
                         +IFF_PROMISC+ (ifreq.flags ifr)))
            (sb-unix:unix-ioctl fd +SIOCSIFFLAGS+ (alien-sap ifr)))))))

(defun bind-to-interface (fd interface-index protocol)
  (declare #.*muffle-compiler-note*)
  (with-zeroset-alien (sll sockaddr-ll)
    (setf (slot sll 'family) +PF_PACKET+
          (slot sll 'protocol) (to-network-order protocol 2)
          (slot sll 'ifindex) interface-index)
    (when (= 0 (bind fd (cast sll (* sockaddr)) sockaddr-ll.size))
      fd)))

(defun make-packet-fd (interface-name protocol)
  (let ((name (if (stringp interface-name) 
                  interface-name
                (string-downcase (string interface-name)))))
    (named.when (fd (%make-packet-fd protocol))
      (named.when (if-idx (interface-index fd name))
        (bind-to-interface fd if-idx protocol)))))

(defstruct (channel (:constructor 
                     make-channel 
                     (fd buffer-size &aux (buffer (make-buffer buffer-size)))))
  (fd     0 :type fixnum)
  (buffer 0 :type (alien (* (unsigned 8))))
  (buffer-size 0 :type fixnum))

(defun flush (channel)
  (loop FOR frame = (read-frame channel :dont-wait t)
        WHILE frame
        SUM (length frame)))

(defun make (interface-name protocol &key (buffer-size 2048))
  (named.when (fd (make-packet-fd interface-name protocol))
    (named.when (cnl (make-channel fd buffer-size))
      (flush cnl)
      cnl)))

(defparameter *listen-buf* (make-alien (array (unsigned 8) 1)))
(defun listen (channel)
  (with-slots (fd) channel
    (let ((ret (recv fd *listen-buf* 1 (logior +MSG_PEEK+ +MSG_DONTWAIT+))))
      (case ret
        ((-1 0) nil)
        (otherwise t)))))

(defun close (channel)
  (with-slots (fd buffer) channel
    (free-alien buffer)
    (values (sb-unix:unix-close fd))))

(defun parse-ethernet-header (frame)
  (if (< (length frame) 14)
      (values nil nil nil)
    (flet ((ref (i) (aref frame i)))
      (values (format nil "~@{~2,'0x~^:~}"
                      (ref 0) (ref 1) (ref 2) (ref 3) (ref 4) (ref 5))
              (format nil "~@{~2,'0x~^:~}"
                      (ref 6) (ref 7) (ref 8) (ref 9) (ref 10) (ref 11))
              ;; TODO:
              (+ (ash (ref 12) 8) (ref 13))))))

(defun read-frame (channel &key dont-wait)
  (with-slots (fd buffer buffer-size) channel
    (let ((ret (recv fd buffer buffer-size (if dont-wait +MSG_DONTWAIT+ 0))))
      (case ret
        (-1 (if (eq (get-errno) +EAGAIN+)
                (values nil t nil nil nil)
              (values nil nil nil nil nil)))
        (0 (values nil t nil nil nil))
        (t (let ((frame (make-array ret :element-type '(unsigned-byte 8))))
             (dotimes (i ret)
               (setf (aref frame i) (deref buffer i)))
             (multiple-value-bind (to from type)
                                  (parse-ethernet-header frame)
               (values frame t from to type))))))))


(defun write-frame (bytes channel)
  (with-slots (fd buffer buffer-size) channel
    (assert (< (length bytes) buffer-size))
    (dotimes (i (length bytes))
      (setf (deref buffer i) (aref bytes i)))
    (let ((ret (send fd buffer (length bytes) 0)))
      (case ret
        (-1 nil)
        (t  ret)))))

#|
./linux/if_ether.h:#define ETH_P_LOOP	0x0060		/* Ethernet Loopback packet	*/
./linux/if_ether.h:#define ETH_P_PUP	0x0200		/* Xerox PUP packet		*/
./linux/if_ether.h:#define ETH_P_PUPAT	0x0201		/* Xerox PUP Addr Trans packet	*/
./linux/if_ether.h:#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
./linux/if_ether.h:#define ETH_P_X25	0x0805		/* CCITT X.25			*/
./linux/if_ether.h:#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/
./linux/if_ether.h:#define	ETH_P_BPQ	0x08FF		/* G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ] */
./linux/if_ether.h:#define ETH_P_IEEEPUP	0x0a00		/* Xerox IEEE802.3 PUP packet */
./linux/if_ether.h:#define ETH_P_IEEEPUPAT	0x0a01		/* Xerox IEEE802.3 PUP Addr Trans packet */
./linux/if_ether.h:#define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
./linux/if_ether.h:#define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
./linux/if_ether.h:#define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
./linux/if_ether.h:#define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
./linux/if_ether.h:#define ETH_P_LAT       0x6004          /* DEC LAT                      */
./linux/if_ether.h:#define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
./linux/if_ether.h:#define ETH_P_CUST      0x6006          /* DEC Customer use             */
./linux/if_ether.h:#define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
./linux/if_ether.h:#define ETH_P_TEB	0x6558		/* Trans Ether Bridging		*/
./linux/if_ether.h:#define ETH_P_RARP      0x8035		/* Reverse Addr Res packet	*/
./linux/if_ether.h:#define ETH_P_ATALK	0x809B		/* Appletalk DDP		*/
./linux/if_ether.h:#define ETH_P_AARP	0x80F3		/* Appletalk AARP		*/
./linux/if_ether.h:#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
./linux/if_ether.h:#define ETH_P_IPX	0x8137		/* IPX over DIX			*/
./linux/if_ether.h:#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
./linux/if_ether.h:#define ETH_P_PAUSE	0x8808		/* IEEE Pause frames. See 802.3 31B */
./linux/if_ether.h:#define ETH_P_SLOW	0x8809		/* Slow Protocol. See 802.3ad 43B */
./linux/if_ether.h:#define ETH_P_WCCP	0x883E		/* Web-cache coordination protocol
./linux/if_ether.h:#define ETH_P_PPP_DISC	0x8863		/* PPPoE discovery messages     */
./linux/if_ether.h:#define ETH_P_PPP_SES	0x8864		/* PPPoE session messages	*/
./linux/if_ether.h:#define ETH_P_MPLS_UC	0x8847		/* MPLS Unicast traffic		*/
./linux/if_ether.h:#define ETH_P_MPLS_MC	0x8848		/* MPLS Multicast traffic	*/
./linux/if_ether.h:#define ETH_P_ATMMPOA	0x884c		/* MultiProtocol Over ATM	*/
./linux/if_ether.h:#define ETH_P_ATMFATE	0x8884		/* Frame-based ATM Transport
./linux/if_ether.h:#define ETH_P_PAE	0x888E		/* Port Access Entity (IEEE 802.1X) */
./linux/if_ether.h:#define ETH_P_AOE	0x88A2		/* ATA over Ethernet		*/
./linux/if_ether.h:#define ETH_P_TIPC	0x88CA		/* TIPC 			*/
./linux/if_ether.h:#define ETH_P_1588	0x88F7		/* IEEE 1588 Timesync */
./linux/if_ether.h:#define ETH_P_FCOE	0x8906		/* Fibre Channel over Ethernet  */
./linux/if_ether.h:#define ETH_P_FIP	0x8914		/* FCoE Initialization Protocol */
./linux/if_ether.h:#define ETH_P_EDSA	0xDADA		/* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
./linux/if_ether.h:#define ETH_P_802_3	0x0001		/* Dummy type for 802.3 frames  */
./linux/if_ether.h:#define ETH_P_AX25	0x0002		/* Dummy protocol id for AX.25  */
./linux/if_ether.h:#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
./linux/if_ether.h:#define ETH_P_802_2	0x0004		/* 802.2 frames 		*/
./linux/if_ether.h:#define ETH_P_SNAP	0x0005		/* Internal only		*/
./linux/if_ether.h:#define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only     */
./linux/if_ether.h:#define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
./linux/if_ether.h:#define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
./linux/if_ether.h:#define ETH_P_LOCALTALK 0x0009		/* Localtalk pseudo type 	*/
./linux/if_ether.h:#define ETH_P_CAN	0x000C		/* Controller Area Network      */
./linux/if_ether.h:#define ETH_P_PPPTALK	0x0010		/* Dummy type for Atalk over PPP*/
./linux/if_ether.h:#define ETH_P_TR_802_2	0x0011		/* 802.2 frames 		*/
./linux/if_ether.h:#define ETH_P_MOBITEX	0x0015		/* Mobitex (kaz@cafe.net)	*/
./linux/if_ether.h:#define ETH_P_CONTROL	0x0016		/* Card specific control frames */
./linux/if_ether.h:#define ETH_P_IRDA	0x0017		/* Linux-IrDA			*/
./linux/if_ether.h:#define ETH_P_ECONET	0x0018		/* Acorn Econet			*/
./linux/if_ether.h:#define ETH_P_HDLC	0x0019		/* HDLC frames			*/
./linux/if_ether.h:#define ETH_P_ARCNET	0x001A		/* 1A for ArcNet :-)            */
./linux/if_ether.h:#define ETH_P_DSA	0x001B		/* Distributed Switch Arch.	*/
./linux/if_ether.h:#define ETH_P_TRAILER	0x001C		/* Trailer switch tagging	*/
./linux/if_ether.h:#define ETH_P_PHONET	0x00F5		/* Nokia Phonet frames          */
./linux/if_ether.h:#define ETH_P_IEEE802154 0x00F6		/* IEEE802.15.4 frame		*/
|#
