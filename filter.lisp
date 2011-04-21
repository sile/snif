(in-package :snif)

(defstruct (filter (:constructor filter (fun &key (layer 2))))
  fun
  layer)

(defun acceptable-p (filter obj octets)
  (declare (ignorable octets))
  ;; TODO: (filter-layer filter)
  (funcall (filter-fun filter) obj))

(defun filter-port (port) ; or source destination
  (filter (lambda (obj) 
           (typecase (ignore-errors #1=(ip-packet-data (eth-frame-data obj))) ;; XXX:
              ((or tcp-packet udp-packet)
               (with-slots (header) #1#
                 (with-slots (src-port dst-port) header
                   (or (eql src-port port)
                       (eql dst-port port)))))
              (otherwise nil)))
            :layer 4))
    

