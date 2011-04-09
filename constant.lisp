(in-package :snif)

(defconstant +PF_PACKET+ 17)
(defconstant +SOCK_RAW+ 3)

(defconstant +MSG_DONTWAIT+ #x40)
(defconstant +MSG_PEEK+ #x02)
(defconstant +EAGAIN+ 11)

(defconstant +IFNAMSIZ+ 16)
(defconstant +IFF_PROMISC+ #x100)
(defconstant +SIOCGIFFLAGS+ #x8913)
(defconstant +SIOCSIFFLAGS+ #x8914)
(defconstant +SIOCGIFINDEX+ #x8933)

(defparameter *protocols*
  (list
   (defconstant ETH_P_ALL #x0003)
   (defconstant ETH_P_IP #x0800)
   (defconstant ETH_P_LOOP #x0060)
   (defconstant ETH_P_ARP #x0806)
   (defconstant ETH_P_RARP #x8035)
   ))
