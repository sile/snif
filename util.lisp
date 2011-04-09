(in-package :snif)

(defun reverse-order (int size)
  (loop FOR i FROM 0 TO size
        FOR j FROM (1- size) DOWNTO 0
        WHILE (< i j)
    DO
    (rotatef (ldb (byte 8 (* i 8)) int)
             (ldb (byte 8 (* j 8)) int)))
  int)

(defun to-network-order (int size)
  (declare (ignorable size))
  #.(if (eq *native-endian* :big)
        'int
      '(reverse-order int size)))

(defun strncpy (buf str max)
  (dotimes (i (min (length str) max))
    (setf (deref buf i) (char-code (aref str i))))
  (when (< (length str) max)
    (setf (deref buf (length str)) (char-code #\Null)))
  buf)

(defun mem-zero-set (sap size)
  (let ((*p (cast sap (* (unsigned 8)))))
    (dotimes (i size sap)
      (setf (deref *p i) 0))))

(defun mksym (&rest args)
  (intern (format nil "~{~:@(~A~)~}" args)))

(defmacro with-zeroset-alien ((var type) &body body)
  `(with-alien ((,var ,type))
     (mem-zero-set ,var ,(mksym type ".SIZE"))
     ,@body))

(defmacro a.when (exp &body body)
  `(let ((it ,exp))
     (when it
       ,@body)))

(defmacro named.when ((var exp) &body body)
  `(let ((,var ,exp))
     (when ,var
       ,@body)))

(defun make-buffer (size) (make-alien (unsigned 8) size))
