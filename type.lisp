(in-package :snif)

(define-alien-type size_t unsigned-long)
(define-alien-type socklen_t (unsigned 32))
(define-alien-type __be16 (unsigned 16))

(define-alien-type sockaddr
  (struct nil
    (family unsigned-short)
    (data   (array unsigned-char 14))))
(define-symbol-macro sockaddr.size (alien-size sockaddr :bytes))
(defmacro sockaddr.family (o) `(slot ,o 'family))
(defmacro sockaddr.data (o) `(slot ,o 'data))

(define-alien-type ifreq
  (struct nil
    (name (array char #.+IFNAMSIZ+))
    (u (union nil
         (index int)
         (flags short)
         (hwaddr sockaddr)
         (__ (array char #.+IFNAMSIZ+))))))
(define-symbol-macro ifreq.size (alien-size ifreq :bytes))
(defmacro ifreq.name (o) `(slot ,o 'name))
(defmacro ifreq.index (o) `(slot (slot ,o 'u) 'index))
(defmacro ifreq.flags (o) `(slot (slot ,o 'u) 'flags))
(defmacro ifreq.hwaddr (o) `(slot (slot ,o 'u) 'hwaddr))

(define-alien-type sockaddr-ll
  (struct nil
    (family   unsigned-short)
    (protocol __be16)
    (ifindex  int)
    (hatype   unsigned-short)
    (pkttype  unsigned-char)
    (halen    unsigned-char)
    (addr     (array unsigned-char 8))))
(define-symbol-macro sockaddr-ll.size (alien-size sockaddr-ll :bytes))
(defmacro sockaddr-ll.family (o) `(slot ,o 'family))
(defmacro sockaddr-ll.protocol (o) `(slot ,o 'protocol))
(defmacro sockaddr-ll.ifindex (o) `(slot ,o 'ifindex))
(defmacro sockaddr-ll.hatype (o) `(slot ,o 'hatype))
(defmacro sockaddr-ll.pkttype (o) `(slot ,o 'pkttype))
(defmacro sockaddr-ll.halen (o) `(slot ,o 'halen))
(defmacro sockaddr-ll.addr (o) `(slot ,o 'addr))
