(defpackage snif
  (:use :common-lisp :sb-alien)
  (:shadow :common-lisp listen close flush)
  (:export capture
           
           make-packet-fd
           promisc-mode
           set-promisc-mode
           listen-packet ; XXX:
           read-packet
           write-packet
           
           channel
           make
           flush
           listen
           close
           read-frame
           write-frame
           
           ETH_P_ALL
           ETH_P_IP))
(in-package :snif)

(defvar *muffle-compiler-note* '(sb-ext:muffle-conditions sb-ext:compiler-note))

(defvar *native-endian* 
  (if (eq sb-c:*backend-byte-order* :big-endian) :big :little))
