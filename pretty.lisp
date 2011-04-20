(in-package :snif)
;; TODO: bit-stream

;; icmp: 
(defstruct icmp-header.echo
  type ; 8
  code ; 8
  checksum ; 16
  id ; 16
  seq-num ; 16
  )

(defstruct icmp-header.general
  type ; 8
  code ; 8
  checksum ; 16
  opaque)

(defstruct icmp-packet
  header
  data)

(defun parse-icmp-header (octets)
  (let ((type (aref octets 0))
        (code (aref octets 1)))
    (case type
      ((0 8) (make-icmp-header.echo 
              :type type
              :code code
              :checksum (parse-int octets 2 4)
              :id (parse-int octets 4 6)
              :seq-num (parse-int octets 6 8)))
      (otherwise
       (make-icmp-header.general
        :type type
        :code code
        :checksum (parse-int octets 2 4)
        :opaque (subseq octets 4))))))
    
(defun parse-icmp-packet (octets)
  (when (>= (length octets) 8)
    (make-icmp-packet
     :header (parse-icmp-header octets)
     :data (subseq octets 8))))

;; ip
(defstruct ip-packet
  header
  data)

(defstruct ip4-header
  version         ; 4
  header-length   ; 4
  type-of-service ; 8
  packet-length   ; 16
  id              ; 16
  flags           ; 3
  fragment-offset ; 13
  ttl             ; 8
  protocol        ; 8
  checksum        ; 16
  src-addr        ; 32
  dst-addr        ; 32
  option)         ; varying: 0..(header-length*32 - 160)

(defun parse-ip4-header (octets)
  (when (> (length octets) 20)
    (flet ((ref (n) (aref octets n)))
      (make-ip4-header
       :version (ldb (byte 4 4) (ref 0))
       :header-length #1=(ldb (byte 4 0) (ref 0))
       :type-of-service (ref 1)
       :packet-length (parse-int octets 2 4)
       :id (parse-int octets 4 6)
       :flags (ldb (byte 3 5) (ref 6))
       :fragment-offset (+ (ash (ldb (byte 5 0) (ref 6)) 8)
                           (ref 7))
       :ttl (ref 8)
       :protocol (ref 9)
       :checksum (parse-int octets 10 12)
       :src-addr (subseq octets 12 16)
       :dst-addr (subseq octets 16 20)
       :option (subseq octets 20 (* #1# 4))
       ))))

(defun parse-ip-header (octets)
  (case (ldb (byte 4 4) (aref octets 0))
    (4 (let ((h (parse-ip4-header octets)))
         (values h (* (ip4-header-header-length h) 4))))
    (6 nil)
    (otherwise nil)))

(defun parse-ip-packet (octets)
  (when (> (length octets) 0)
    (multiple-value-bind (header length)
                         (parse-ip-header octets)
      (when header
        (let ((data (subseq octets length)))
         (make-ip-packet
         :header header 
         :data (case (ip4-header-protocol header)  ; XXX: 
                 (1 (or (parse-icmp-packet data) data))
                 (6 (or (parse-tcp-packet data) data))
                 (otherwise data))))))))

;; ethernet
(defstruct eth-frame
  src-mac
  dst-mac
  type
  data
  fcs)  ; frame check sequence

(defconstant +MIN_ETH_FRAME_LENGTH+ 18)

(defun parse-int (octets &optional (start 0) (end (length octets)))
  (loop FOR offset FROM 0 BY 8
        FOR i FROM (1- end) DOWNTO start
    SUM (ash (aref octets i) offset)))

(defun parse-eth-frame (octets)
  (when (> (length octets) +MIN_ETH_FRAME_LENGTH+)
    (let ((type (parse-int octets 12 14))
          (data (subseq octets 14 (- (length octets) 0)))) ; XXX: trailerは入らない?
      (make-eth-frame
       :src-mac (subseq octets 0 6)
       :dst-mac (subseq octets 6 12)
       :type type
       :data (or (case type
                   (#x0800 (parse-ip-packet data)))
                 data)
       :fcs (parse-int octets (- (length octets) 0))))))


;; tcp
(defstruct tcp-packet
  header
  data)

(defstruct tcp-header
  src-port ; 16
  dst-port ; 16
  seq-num ; 32
  ack-num ; 32
  header-length ; 4  # * 32 bit -> length
  reserved ; 4
  bit.cwr ; 1
  bit.ece ; 1
  bit.urg ; 1
  bit.ack ; 1
  bit.psh ; 1
  bit.rst ; 1
  bit.syn ; 1
  bit.fin ; 1
  window-size ; 16
  checksum ; 16
  urgent-pointer ; 16
  option ; varying# 0..(header-length*32 - 160)
  )

(defun parse-tcp-header (octets)
  (let ((h 
    (make-tcp-header
     :src-port (parse-int octets 0 2)
     :dst-port (parse-int octets 2 4)
     :seq-num (parse-int octets 4 8)
     :ack-num (parse-int octets 8 12)
     :header-length #2=(ldb (byte 4 4) (aref octets 12))
     :reserved (ldb (byte 4 0) (aref octets 12))
     :bit.cwr (ldb-test (byte 1 7) #1=(aref octets 13))
     :bit.ece (ldb-test (byte 1 6) #1#)
     :bit.urg (ldb-test (byte 1 5) #1#)
     :bit.ack (ldb-test (byte 1 4) #1#)
     :bit.psh (ldb-test (byte 1 3) #1#)
     :bit.rst (ldb-test (byte 1 2) #1#)
     :bit.syn (ldb-test (byte 1 1) #1#)
     :bit.fin (ldb-test (byte 1 0) #1#)
     :window-size (parse-int octets 14 16)
     :checksum (parse-int octets 16 18)
     :urgent-pointer (parse-int octets 18 20)
     :option (subseq octets 20 (* #2# 4))))) ; TODO: (defstruct tcp-option)
    (values h
            (* (tcp-header-header-length h) 4))))

(defun parse-tcp-packet (octets)
  (when (>= (length octets) 20)
    (multiple-value-bind (header length) 
                         (parse-tcp-header octets)
      (make-tcp-packet 
       :header header 
       :data 
       (subseq octets length)
       #+DEV
       (list (map 'string
                        (lambda (o)
                          (if (and (< o #x80)
                                   (graphic-char-p (code-char o)))
                              (code-char o)
                            #\.))
                        (subseq octets length))
                   (subseq octets length))))))
  