(in-package :snif)

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
                     new-channel 
                     (fd buffer-size &aux (buffer (make-buffer buffer-size)))))
  (fd     0 :type fixnum)
  (buffer 0 :type (alien (* (unsigned 8))))
  (buffer-size 0 :type fixnum))

(defun flush (channel)
  (loop FOR frame = (read-frame channel :dont-wait t)
        WHILE frame
        SUM (length frame)))

(defun make-channel (interface-name protocol &aux (buffer-size 2048))
  (named.when (fd (make-packet-fd interface-name (find-protocol-by-name protocol)))
    (named.when (cnl (new-channel fd buffer-size))
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

(defmacro with-channel ((var interface-name &key (protocol :all) promisc) &body body)
  `(let ((,var (make-channel ,interface-name ,protocol)))
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

(defun sniffering (interface-name &key (protocol :all) promisc)
  (with-channel (cnl interface-name :protocol protocol :promisc promisc)
    (loop 
     (multiple-value-bind (octets ok source destination protocol) 
                          (read-frame cnl)
       (when ok
         (format t "~&; ~A -> ~A [~A]~%" source destination protocol)
         )))))
