digest: digest.c
	gcc digest.c -o digest -I /opt/homebrew/opt/p11-kit/include/p11-kit-1/p11-kit/ -ldl

encrypt: encrypt.c
	gcc encrypt.c -o encrypt -I /opt/homebrew/opt/p11-kit/include/p11-kit-1/p11-kit/ -ldl
