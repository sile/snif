(in-package :snif)

(defun %make-packet-fd (protocol)
  (let ((fd (socket +PF_PACKET+ +SOCK_RAW+ (to-network-order protocol 2))))
    (alien-assert (/= fd -1) :make-packet-fd)
    fd))

(defmacro with-ifreq ((var interface-name) &body body)
  `(with-zeroset-alien (,var ifreq)
     (strncpy (ifreq.name ,var) ,interface-name +IFNAMSIZ+)
     ,@body))

(defun interface-index (fd interface-name &aux (name interface-name))
  (declare #.*muffle-compiler-note*)
  (with-ifreq (ifr name)
    (alien-assert (sb-unix:unix-ioctl fd +SIOCGIFINDEX+ (alien-sap ifr)) :get-interface-index name)
    (ifreq.index ifr)))

(defun promisc-mode (interface-name &aux (name interface-name))
  (declare #.*muffle-compiler-note*)
  (let ((fd (%make-packet-fd ETH_P_ALL)))
    (with-ifreq (ifr name)
      (alien-assert (sb-unix:unix-ioctl fd +SIOCGIFFLAGS+ (alien-sap ifr)) :get-interface-flags name)
      (logtest +IFF_PROMISC+ (ifreq.flags ifr)))))

(defun set-promisc-mode (interface-name enable &aux (name interface-name))
  (declare #.*muffle-compiler-note*)
  (let ((fd (%make-packet-fd ETH_P_ALL)))
    (with-ifreq (ifr name)
      (alien-assert (sb-unix:unix-ioctl fd +SIOCGIFFLAGS+ (alien-sap ifr)) :get-interface-flags name)
      (setf (ifreq.flags ifr)
            (boole (if enable boole-ior boole-andc1) 
                   +IFF_PROMISC+ (ifreq.flags ifr)))
      (alien-assert (sb-unix:unix-ioctl fd +SIOCSIFFLAGS+ (alien-sap ifr)) :set-interface-flags name)))
  t)

(defun bind-to-interface (fd interface-index protocol)
  (declare #.*muffle-compiler-note*)
  (with-zeroset-alien (sll sockaddr-ll)
    (setf (slot sll 'family) +PF_PACKET+
          (slot sll 'protocol) (to-network-order protocol 2)
          (slot sll 'ifindex) interface-index)
    (alien-assert (= 0 (bind fd (cast sll (* sockaddr)) sockaddr-ll.size)) :bind)
    fd))

(defun make-packet-fd (interface-name protocol)
  (let ((name (if (stringp interface-name) 
                  interface-name
                (string-downcase (string interface-name)))))
    (let* ((fd (%make-packet-fd protocol))
           (if-idx (interface-index fd name)))
      (bind-to-interface fd if-idx protocol))))

(defstruct (channel (:constructor 
                     new-channel 
                     (fd buffer-size &aux (buffer (make-buffer buffer-size)))))
  (fd     0 :type fixnum)
  (buffer 0 :type (alien (* (unsigned 8))))
  (buffer-size 0 :type fixnum))

(defun flush (channel)
  (loop FOR frame = (read-frame channel :dont-wait t)
        WHILE frame
        SUM (length frame)))

(defun make-channel (interface-name &key (protocol :all) &aux (buffer-size 2048))
  (assert (find-protocol-by-name protocol) () 
          "protocol ~s is undefined. (LIST-ALL-PROTOCOLS function provides avaiable protocol list)" protocol)
  (let* ((fd (make-packet-fd interface-name (find-protocol-by-name protocol)))
         (cnl (new-channel fd buffer-size)))
    (flush cnl)
    cnl))

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

(defmacro with-channel ((var interface-name &key (protocol :all) promisc) &body body)
  `(let ((,var (make-channel ,interface-name :protocol ,protocol)))
     (when ,promisc
       (set-promisc-mode ,interface-name t))
     (unwind-protect
         (locally ,@body)
       (when ,promisc
         (set-promisc-mode ,interface-name nil))
       (close ,var))))

(defun parse-ethernet-header (frame)
  (if (< (length frame) 14)
      (values nil nil nil)
    (flet ((ref (i) (aref frame i)))
      (values (format nil "~(~@{~2,'0x~^:~}~)"
                      (ref 0) (ref 1) (ref 2) (ref 3) (ref 4) (ref 5))
              (format nil "~(~@{~2,'0x~^:~}~)"
                      (ref 6) (ref 7) (ref 8) (ref 9) (ref 10) (ref 11))
              (find-protocol-by-value (+ (ash (ref 12) 8) (ref 13)))))))

(defun read-frame (channel &key dont-wait)
  (with-slots (fd buffer buffer-size) channel
    (let ((ret (recv fd buffer buffer-size (if dont-wait +MSG_DONTWAIT+ 0))))
      (case ret
        (-1 (alien-assert (eq (get-errno) +EAGAIN+) :read-frame)
            (values nil nil nil nil))
        (0 (values nil nil nil nil))
        (t (let ((frame (make-array ret :element-type '(unsigned-byte 8))))
             (dotimes (i ret)
               (setf (aref frame i) (deref buffer i)))
             (multiple-value-bind (to from type)
                                  (parse-ethernet-header frame)
               (values frame from to type))))))))

(defun write-frame (octets channel)
  (with-slots (fd buffer buffer-size) channel
    (assert (< (length octets) buffer-size))
    (dotimes (i (length octets))
      (setf (deref buffer i) (aref octets i)))
    (let ((len (send fd buffer (length octets) 0)))
      (alien-assert (/= -1 len) :write-frame)
      len)))

(defun sniffing (interface-name &key (protocol :all) promisc (columns 16) pretty)
  (declare (ignorable columns))
  (with-channel (cnl interface-name :protocol protocol :promisc promisc)
    (loop 
     (multiple-value-bind (octets source destination protocol) 
                          (read-frame cnl)
       (declare (ignorable source destination protocol))
       (if pretty
       (when octets
         (let* ((frame (parse-eth-frame octets)))
         (print 
          frame
          *error-output*
         )))
       (when octets
         (format t "~&;# ~A -> ~A [~A]~%" source destination protocol)
         (loop WITH column-num = columns
               FOR row FROM 0 
               WHILE (< (* row column-num) (length octets))
           DO
           (format t ";[~(~3,'0x~)]" (* row column-num))
           (loop FOR column FROM 0 BELOW column-num
                 FOR i = (+ (* row column-num) column)
                 WHILE (< i (length octets))
                 DO 
                 (format t " ~(~2,'0x~)" (aref octets i)))
           (format t "~vt" (+ 7 (* column-num 3)))
           (loop FOR column FROM 0 BELOW column-num
                 FOR i = (+ (* row column-num) column)
                 WHILE (< i (length octets))
                 FOR c = (code-char (aref octets i))
                 DO 
                 (format t "~c" (if (and (standard-char-p c)
                                         (graphic-char-p c))
                                    c
                                  #\.)))
           (terpri))
         (format t ";~%")))))))
