(in-package :snif)

(eval-when (:load-toplevel) 
  (define-alien-routine socket int (domain int) (type int) (protocol int))
  (define-alien-routine bind int (sockfd int) (my-addr (* sockaddr)) (addrlen socklen_t))
  (define-alien-routine send int (sockfd int) (buf (* t)) (len size_t) (flags int))
  (define-alien-routine sendto int (sockfd int) (buf (* t))
                                   (len size_t) (flags int)
                                   (dest_addr (* sockaddr)) (addrlen socklen_t))
  (define-alien-routine recv int (socketfd int) (buf (* t)) (len size_t) (flags int)))
