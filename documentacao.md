# Funcionamento do OAEP
O RSA é um algoritmo de criptografia determinístico — dada uma mensagem e uma chave pública, a mesma cifração é gerada. Isso gera brechas para ataques baseados em análises estatísticas ou de texto escolhido. O OAEP é uma técnica de preenchimento da mensagem a ser cifrada que serve para eliminar o determinismo do algoritmo RSA.
O OAEP utiliza um algoritmo chamado MGF1, que transforma uma entrada (seed) em uma saída de tamanho exato $k$. O MGF1 recebe a quantidade de bytes $k$ e a seed, e define uma string vazia como resultado. A partir disso ele itera quantas vezes for preciso com um incrementador, adicionando nessa string vazia o digest (saída) de uma função hash (utilizamos SHA-1) aplicado ao seed concatenado com o incrementador. Retorna então os $k$ primeiros bytes do resultado, descartando qualquer excedente. O OAEP tem como entrada a mensagem a ser cifrada em bytes, $k$ e um rótulo (ou 'label'). Primeiramente calcula o hash com SHA-1 do rótulo e monta um bloco de dados, que é composto por este último hash calculado, uma sequência de zeros chamada _padding string_, um bite `0x01` separador e então a mensagem original. Através de uma função que gera uma seed pseudorrandômica, aplica o MGF1 sobre esta seed e então executa um XOR bit a bit com o bloco de dados e o resultado do MFG1, o que resulta em `maskedDB`. A própria seed é embaralhada utilizando o MGF1 tendo como entrada o `maskedDB`, gerando `maskedSeed`. O resultado final é uma string: `0x00` seguido de `maskedSeed` seguido de `maskedDB`. O resultado final tem tamanho exato $k$. Essa é a string que será cifrada com o algoritmo RSA. Após a decodificação da mensagem cifrada pelo RSA, é possível recuperar a mensagem revertendo todo o processo.
# Funcionamento do RSA
A função RSA utiliza uma mensagem $m$, um número $e$ chamado de expoente público e um número $n$, sendo o texto cifrado igual à $c = m^{e} \mod n$. Apenas quem conhece $d$, a chave privada, consegue recuperar a mensagem original. De onde vem, exatamente, cada um desses termos? Esses números compõem as chaves públicas e privadas, geradas da seguinte forma: primeiro se gera primos $p_{1}$ e $p_{2}$, e então se calcula $n = p_{1} \times p_{2}$. A função totiente de euler $\varphi(n) = (p_{1}-1) \times (p_{2}-1)$ também é calculada. O expoente público é um número escolhido da seguinte forma: ele precisa ser maior que 1, menor que $\varphi(n)$ (a função totiente de Euler) e coprimo com $\varphi(n)$, isto é, o máximo divisor comum entre o expoente público e esse valor deve ser 1. Por padrão, usamos o número 3 como expoente público, mas ele é incrementado indefinidamente enquanto ele não for coprimo com $\varphi(n)$. Esses termos possuírem como máximo divisor comum o 1 nos garante que haverá um $d$ tal que $e \times d$ é congruente a 1 módulo $\varphi(n)$, que é uma propriedade necessária para que a decifração ocorra. A partir desses cálculos nós geramos a chave pública $(n, e)$ e a privada $(n, d)$. Que conhece $d$ pode aplicar o seguinte cálculo $m = c^{d} \mod n$.
# Funções-chave de primos.py
- Função `seed_bigint`
	   Usa o tempo do sistema para devolver um número. Possui um incrementador para que chamadas consecutivas produzam necessariamente números distintos.
- Função `random_bigint`
	    Produz um número pseudoaleatório através do algoritmo Linear Congruential Generator, que recebe uma seed (no caso, a seed vem da função seed_bigint) e então aplica uma operação com multiplicador, incremento e módulo.
- Função `fast_modular_exponentiation`
	Seja uma base $b$, um expoente $e$ e um número inteiro $m$, esta função retorna $b^{e} \mod m$.
- Função `miller_rabin_test`
	Uma função que implementa o teste de Miller-Rabin, um teste probabilístico de primalidade. 
- Função `iterate_miller_rabin`
	Usada para repetir o teste de Miller-Rabin $k$ vezes, sendo $k$ uma entrada da função.
- Função `gera_primo`
	Gera números aleatórios até que um passe no teste de Miller-Rabin com 3 repetições.
# Funções-chave de oaep.py
- Função `gen_mask_mgf1`
    Esta função usa o algoritmo mgf1 para gerar uma máscara — uma sequência de caracteres que será usada para modificar outro dado, no caso, a mensagem que iremos cifrar. Isso será feito por uma operação xor. O algoritmo mgf1 recebe um seed $s$ e iterativamente aplica um hash em cima de $s$ somado a um valor incrementado com o passar das iterações. O resultado é a concatenação de todas essas aplicações cortado com o tamanho que se queira.
    Referência: https://en.wikipedia.org/wiki/Mask_generation_function
- Função `xor_bytes`
    Dadas duas entradas $a$ e $b$ do tipo byte e do mesmo tamanho, faz um xor em $a$ e $b$. O xor será feito com a mensagem a ser cifrada e a máscara.
- Funções `oaep_encode` e `oaep_decode`
	Cifração e decifração do OAEP segundo a descrição do algoritmo OAEP dada acima.
- Funções `cypher` e `decypher`
	Em `cypher` é aplicado o OAEP na mensagem e então se aplica o RSA. Em decypher, se decifra o RSA e então se decifra o OAEP.
# Funções-chave de rsa.py
 - Função `gen_rsa_key`
	 Gera as chaves RSA segundo a descrição do algoritmo RSA dada acima.
- Funções `rsa_encrypt` e `rsa_decrypt`
	Encripta e decripta a mensagem segundo a descrição do algoritmo RSA dada acima.
# Funcionamento do SHA3
O algoritmo SHA3-256 é um membro da família de padrões de algoritmos de hash criptográfico seguro que transforma uma mensagem de qualquer tamanho em um valor fixo de 256 bits (32 bytes), chamado de digest. A ideia principal por trás de uma função de hash é que, dado um conteúdo de entrada, ela sempre gera a mesma saída, mas mesmo uma pequena alteração na entrada resulta em um digest completamente diferente. Além disso, funções de hash como o SHA3 são projetadas para serem unidirecionais — ou seja, é computacionalmente inviável recuperar a mensagem original a partir do hash. A entrada `message` deve ser um dado em formato de bytes. A função `hashlib.sha3_256()` inicializa o algoritmo, e o método `.update(message)` alimenta a função com a mensagem a ser processada. O resultado é obtido com `.digest()`, que retorna o valor do hash em bytes. Para obter esse valor em formato legível foi empregado a base64 para codificá-lo.
# Funcionamento da Base64
A codificação Base64 é usada para transformar uma sequência de bytes, dados binários, em uma sequência de caracteres ASCII, string de texto, que pode ser transmitida com segurança por canais que não suportam dados binários. Os dados de entrada — por exemplo, um hash gerado por SHA3 — são passados em forma de bytes para uma função de codificação. O processo consiste em agrupar os bits da mensagem em blocos de 6 em 6 (em vez dos tradicionais 8 bits por byte), pois $2^6 = 64$, o que justifica o nome Base64. Cada grupo de 6 bits é então mapeado para um caractere da tabela Base64. A codificação Base64, portanto, não é um mecanismo de segurança nem criptografia, uma vez que ela não protege os dados, apenas os representa em um formato seguro para transporte e armazenamento textual.
# Funções-chave de hash.py
- Função `hash_sha3_256`
  	Recebe uma mensagem em bytes e retorna seu hash utilizando o algoritmo SHA3, no formato de bytes.
- Função `hash_base64`
  	codifica os dados com `base64.b64encode()` e depois converte o resultado de volta para uma string com `.decode()`. O resultado é uma sequência de caracteres que pode conter letras, números e símbolos como `+`, `/` e `=`.
- Função `base64_to_bytes`
  	Decodifica uma string em Base64 e retorna a sequência original de bytes correspondente.
# Funções-chave de main.py
- Função `gerador_de_assinatura`
  	 Esta função realiza o processo completo de geração de uma assinatura digital para um arquivo, utilizando o esquema RSA com codificação OAEP e hash SHA3-256. Inicialmente, ela lê o conteúdo do arquivo em bytes, gera dois primos aleatórios para compor as chaves RSA e cria o par de chaves pública e privada. Em seguida, cifra a mensagem com a chave pública e a decifra com a chave privada, garantindo a validade do par de chaves. Depois, aplica a função hash à mensagem original e cifra esse hash com a chave privada, gerando a assinatura digital. Tanto a mensagem quanto a assinatura são codificadas em base64 e salvas no arquivo `msg_assinada.json`.
- Função `verificador_de_assinatura`
  	Esta função realiza a verificação da autenticidade de uma assinatura digital previamente gerada, validando se a mensagem recebida corresponde à assinatura associada. Para isso, ela lê de um arquivo JSON os dados assinados — a mensagem e sua assinatura, ambos codificados em base64. Em seguida, decodifica a assinatura usando a chave pública RSA (extraída do par de chaves anteriormente gerado) para obter o hash original da mensagem. Paralelamente, recodifica a mensagem e calcula seu hash atual. Por fim, compara os dois hashes e exibe se a verificação foi bem-sucedida.
