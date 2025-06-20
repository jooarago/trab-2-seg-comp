- Função `gen_mask_mgf1`
	Esta função usa o algoritmo mgf1 para gerar uma máscara — uma sequência de caracteres que será usada para modificar outro dado, no caso, a mensagem que iremos cifrar. Isso será feito por uma operação xor. O algoritmo mgf1 recebe um seed $s$ e iterativamente aplica um hash em cima de $s$ somado a um valor incrementado com o passar das iterações. O resultado é a concatenação de todas essas aplicações cortado com o tamanho que se queira.
	Referência: https://en.wikipedia.org/wiki/Mask_generation_function
- Função `xor_bytes`
	Dadas duas entradas $a$ e $b$ do tipo byte e do mesmo tamanho, faz um xor em $a$ e $b$. O xor será feito com a mensagem a ser cifrada e a máscara. 