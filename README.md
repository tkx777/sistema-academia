# -*- coding: utf-8 -*-
import os
import re
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import ctypes.wintypes # Para tentar pegar a pasta Documentos (embora não usado ativamente com o path fixo)
# import sys # Import 'sys' se for usar sys.version_info para checar versão
import datetime # Adicionado para usar data/hora no relatório
import csv # Adicionado para salvar em formato CSV


BASE_PATH = r"E:\AULA\Aula Python" # <--- caso nessesario trocar caminho
APP_FOLDER_NAME = "Registros"
APP_FOLDER_PATH = os.path.join(BASE_PATH, APP_FOLDER_NAME)
FILE_EXTENSION_TXT = ".txt" # Extensão para arquivo de texto
FILE_EXTENSION_CSV = ".csv" # Extensão para arquivo CSV
SUBFOLDER_ALUNOS = "Alunos"
SUBFOLDER_FUNCIONARIOS = "Funcionarios"
SUBFOLDER_PROFESSORES = "Professores"
# NOVAS Subpastas para formatos de arquivo
SUBFOLDER_TXT = "TXT"
SUBFOLDER_CSV = "CSV"

USUARIOS_FILE_NAME = "usuarios.txt"
USUARIOS_FILE_PATH = os.path.join(APP_FOLDER_PATH, USUARIOS_FILE_NAME)
DEFAULT_ADMIN_USER = "ADM"; DEFAULT_ADMIN_PASS = "administrator" # Senha padrão inicial
ADMIN_ROLE = "admin"; EMPLOYEE_ROLE = "employee"

# Ordem dos campos para salvar em TXT e CSV (importante para CSV header)
CAMPOS_CADASTRO = ["TipoRegistro", "Nome", "Endereço", "Cidade", "Estado", "CPF", "E-mail", "Sexo", "Atividades", "Observação"]

print(f"INFO: Pasta base definida para: {APP_FOLDER_PATH}")
print(f"INFO: Arquivo de usuários definido para: {USUARIOS_FILE_PATH}")

# --- Funções Utilitárias ---

def hash_password(password, salt=None):
    """
    Gera um hash seguro para a senha usando PBKDF2 com salt.

    Esta função utiliza o algoritmo PBKDF2-HMAC-SHA256, que é considerado
    seguro para armazenamento de senhas. O 'salt' adiciona uma camada extra
    de segurança, tornando ataques de rainbow table ineficazes.
    O número de iterações (100000) aumenta o custo computacional para
    calcular o hash, dificultando ataques de força bruta.

    Args:
        password (str): A senha em texto plano a ser hasheada.
        salt (str, optional): O salt em formato hexadecimal. Se None, um novo salt aleatório será gerado.

    Returns:
        tuple: Uma tupla contendo (salt_hex, hash_hex). Retorna (None, None) em caso de erro (ex: salt inválido).
    """
    salt_bytes = None # Inicializa a variável de bytes do salt

    # Passo 1: Obter o salt em formato de bytes
    if salt is None:
        # Se nenhum salt foi fornecido, gerar um novo aleatório
        salt_bytes = os.urandom(16) # Gera 16 bytes aleatórios seguros
        print("DEBUG: Novo salt gerado.")
    else:
        # Se um salt foi fornecido (como string hexadecimal), converter para bytes
        try:
            salt_bytes = bytes.fromhex(salt) # Converte a string hex para bytes
            # Verifica se o salt tem o tamanho esperado (opcional, mas bom)
            if len(salt_bytes) != 16:
                 print(f"AVISO: Salt fornecido tem tamanho {len(salt_bytes)} bytes, esperado 16.")
                 # Poderia retornar erro aqui
        except ValueError:
            # Erro se a string 'salt' não for um hexadecimal válido
            print(f"ERRO: Formato de salt hexadecimal inválido fornecido: {salt}")
            return None, None # Indica falha

    # Passo 2: Calcular o hash usando PBKDF2
    try:
        # Codifica a senha de string para bytes (UTF-8 é padrão)
        password_bytes = password.encode('utf-8')

        # Calcula o hash
        hashed_bytes = hashlib.pbkdf2_hmac(
            hash_name='sha256',         # Algoritmo de hash subjacente
            password=password_bytes,    # Senha em bytes
            salt=salt_bytes,            # Salt em bytes
            iterations=100000,          # Número de iterações (custo)
            dklen=128                   # Tamanho da chave derivada em bytes
        )

        # Passo 3: Converter salt e hash de bytes para hexadecimal (string) para retorno/armazenamento
        salt_hex = salt_bytes.hex()
        hashed_hex = hashed_bytes.hex()

        # Retorna o salt usado e o hash calculado, ambos como strings hexadecimais
        return salt_hex, hashed_hex

    except Exception as e:
        # Captura qualquer outro erro inesperado durante o hashing
        print(f"ERRO inesperado durante o hashing da senha: {e}")
        import traceback
        traceback.print_exc()
        return None, None # Indica falha

def verify_password(stored_salt_hex, stored_hash_hex, provided_password):
    """
    Verifica se a senha fornecida corresponde ao hash armazenado, usando o salt associado.

    Esta função recalcula o hash da senha fornecida usando o mesmo salt
    que foi usado para gerar o hash original. Em seguida, compara de forma segura
    (timing-safe, se disponível) o hash recalculado com o hash armazenado.

    Args:
        stored_salt_hex (str): O salt (em hexadecimal) que foi armazenado junto com o hash.
        stored_hash_hex (str): O hash da senha (em hexadecimal) armazenado no sistema.
        provided_password (str): A senha em texto plano que o usuário forneceu para verificação.

    Returns:
        bool: True se a senha fornecida corresponde ao hash armazenado, False caso contrário ou em caso de erro.
    """
    print(f"DEBUG (verify): Verificando senha para salt={stored_salt_hex[:8]}...") # Mostra parte do salt

    # Passo 1: Recalcular o hash da senha fornecida usando o salt armazenado
    # Chama a mesma função hash_password, passando o salt conhecido
    salt_recalc_hex, recalculated_hash_hex = hash_password(provided_password, stored_salt_hex)

    # Passo 1.1: Verificar se o recálculo foi bem-sucedido
    # Isso pode falhar se o stored_salt_hex for inválido, por exemplo
    if salt_recalc_hex is None or recalculated_hash_hex is None:
        print("ERRO (verify): Falha ao recalcular o hash durante a verificação (salt inválido ou erro no hashing?).")
        return False # Não é possível comparar se o recálculo falhou

    # Passo 2: Comparar o hash recalculado com o hash armazenado de forma segura

    # Comparação segura contra ataques de tempo (timing attacks) é preferível.
    # hashlib.timing_compare está disponível no Python 3.3+

    try:
        # Codificar os hashes hexadecimais (strings) para bytes antes da comparação
        stored_hash_bytes = stored_hash_hex.encode('utf-8')
        recalculated_hash_bytes = recalculated_hash_hex.encode('utf-8')

        # Verificar se a função timing_compare está disponível
        if hasattr(hashlib, 'timing_compare'):
            # Usar a comparação segura
            # print("DEBUG: Usando hashlib.timing_compare para comparação de hash.")
            resultado_comparacao = hashlib.timing_compare(stored_hash_bytes, recalculated_hash_bytes)
            print(f"DEBUG (verify): Resultado da comparação (timing_compare): {resultado_comparacao}")
            return resultado_comparacao
        else:
            # Fallback para comparação direta (menos seguro contra timing attacks)
            print("AVISO: Usando comparação direta de hash (hashlib.timing_compare não disponível).")
            resultado_comparacao = (stored_hash_bytes == recalculated_hash_bytes)
            print(f"DEBUG (verify): Resultado da comparação direta: {resultado_comparacao}")
            return resultado_comparacao

    except Exception as e:
        # Capturar erros durante a comparação (embora menos provável aqui)
        print(f"ERRO DETALHADO ao comparar hashes: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False # Retorna False em caso de erro na comparação

def sanitize_filename(name):
    """
    Limpa um nome para torná-lo seguro para uso como parte de um nome de arquivo.

    - Remove caracteres que são inválidos em nomes de arquivo do Windows/Linux.
    - Substitui um ou mais espaços em branco por um único underscore '_'.
    - Remove underscores que possam ter ficado no início ou fim.
    - Limita o tamanho do nome sanitizado a 100 caracteres.

    Args:
        name (str): O nome original (ex: nome de pessoa).

    Returns:
        str: O nome sanitizado, pronto para ser usado em um nome de arquivo.
    """
    # Passo 1: Remover caracteres inválidos para nomes de arquivo
    # Regex: [\\/*?:"<>|] - Corresponde a qualquer um dos caracteres dentro dos colchetes
    nome_sem_invalidos = re.sub(r'[\\/*?:"<>|]', '', name)
    # print(f"DEBUG Sanitize (Passo 1): '{name}' -> '{nome_sem_invalidos}'")

    # Passo 2: Substituir sequências de espaços por um único underscore
    # Regex: \s+ - Corresponde a um ou mais caracteres de espaço em branco (espaço, tab, etc.)
    nome_com_underscores = re.sub(r'\s+', '_', nome_sem_invalidos)
    # print(f"DEBUG Sanitize (Passo 2): '{nome_sem_invalidos}' -> '{nome_com_underscores}'")

    # Passo 3: Remover underscores do início e do fim, e limitar tamanho
    nome_final_sanitizado = nome_com_underscores.strip('_')[:100]
    # print(f"DEBUG Sanitize (Passo 3): '{nome_com_underscores}' -> '{nome_final_sanitizado}'")

    return nome_final_sanitizado

def verificar_pasta_principal():
    """
    Verifica se a pasta principal da aplicação (APP_FOLDER_PATH) existe.
    Se não existir, tenta criá-la.

    Returns:
        bool: True se a pasta existe ou foi criada com sucesso, False se houve erro ao criar.
    """
    # Verifica se o caminho definido em APP_FOLDER_PATH já existe no sistema de arquivos
    if not os.path.exists(APP_FOLDER_PATH):
        print(f"INFO: Pasta principal '{APP_FOLDER_PATH}' não encontrada. Tentando criar...")
        # Se não existe, tenta criar a pasta (e quaisquer pastas pai necessárias)
        try:
            os.makedirs(APP_FOLDER_PATH)
            print(f"INFO: Pasta principal criada com sucesso em: {APP_FOLDER_PATH}")
            # A criação foi bem-sucedida
            return True
        except OSError as e:
            # Se ocorreu um erro durante a criação (ex: falta de permissão)
            print(f"ERRO CRÍTICO: Não foi possível criar a pasta principal: {APP_FOLDER_PATH}. Erro: {e}")
            # Mostra um erro para o usuário
            messagebox.showerror("Erro Crítico de Diretório",
                                 f"Não foi possível criar a pasta necessária para a aplicação:\n"
                                 f"{APP_FOLDER_PATH}\n\n"
                                 f"Erro: {e}\n\n"
                                 "Verifique as permissões ou o caminho base.")
            # A criação falhou
            return False
        except Exception as e_gen:
             # Captura outros erros inesperados
            print(f"ERRO CRÍTICO: Erro inesperado ao tentar criar a pasta principal: {e_gen}")
            messagebox.showerror("Erro Crítico Inesperado",
                                 f"Ocorreu um erro inesperado ao criar a pasta:\n"
                                 f"{APP_FOLDER_PATH}\n\n"
                                 f"Erro: {e_gen}")
            return False
    else:
        # Se a pasta já existe, nao sera feita outra so usara a msm
        # print(f"DEBUG: Pasta principal já existe
        return True

def verificar_criar_usuarios_file():
    """
    Garante que o arquivo de usuários (usuarios.txt) exista e contenha
    o usuário ADM padrão com hash e salt no formato correto.

    Formato esperado por linha: usuario;salt_hex;hash_hex;role

    Se o arquivo não existe, ele é criado com o usuário ADM.
    Se o arquivo existe mas o ADM não está presente ou está em formato inválido,
    o usuário ADM padrão é adicionado ao final do arquivo.

    Returns:
        bool: True se o arquivo está ok ou foi corrigido/criado com sucesso, False se houve erro.
    """
    # Passo 1: Garante que a pasta principal exista antes de mexer no arquivo
    if not verificar_pasta_principal():
        print("ERRO: Falha ao verificar/criar pasta principal. Não é possível continuar com o arquivo de usuários.")
        return False # Não prosseguir sem a pasta

    # Passo 2: Verificar se o usuário ADM já existe e está no formato correto
    usuario_adm_encontrado_valido = False
    linha_adm_invalida_encontrada = False
    linhas_validas = [] # caso queira reconstruir o arquivo se necessário (não implementado aqui, mas seria ideal)

    # Tenta ler o arquivo se ele existir
    if os.path.isfile(USUARIOS_FILE_PATH):
        print(f"INFO: Arquivo de usuários encontrado: {USUARIOS_FILE_PATH}. Verificando conteúdo...")
        try:
            with open(USUARIOS_FILE_PATH, 'r', encoding='utf-8') as file_handle:
                for numero_linha, line_content in enumerate(file_handle):
                    linha_strip = line_content.strip()

                    # Ignora linhas em branco
                    if not linha_strip:
                        continue

                    # Tenta processar a linha
                    try:
                        # Separa a linha esperando 4 partes: user;salt;hash;role
                        parts = linha_strip.split(';', 3)

                        # Verifica se é a linha do ADM
                        if len(parts) > 0 and parts[0].upper() == DEFAULT_ADMIN_USER:
                            print(f"DEBUG: Linha candidata a ADM encontrada (linha {numero_linha+1}): {parts[0]}")
                            # Verifica se tem todas as 4 partes esperadas (ou pelo menos 3 para salt/hash)
                            if len(parts) == 4:
                                # Verifica se salt e hash parecem ser hexadecimais válidos
                                user_part, salt_part, hash_part, role_part = parts
                                try:
                                    # Tenta converter salt e hash de hex para bytes. Se falhar, lança ValueError.
                                    bytes.fromhex(salt_part)
                                    bytes.fromhex(hash_part)
                                    # Se chegou aqui, o formato parece válido
                                    usuario_adm_encontrado_valido = True
                                    print(f"INFO: Usuário ADM encontrado com formato válido na linha {numero_linha+1}.")
                                    # Poderíamos parar aqui se só precisamos saber se existe um válido
                                    # break # Descomente se quiser parar após encontrar o primeiro ADM válido

                                except ValueError:
                                    # Formato inválido para salt ou hash
                                    print(f"AVISO: Usuário ADM encontrado na linha {numero_linha+1}, mas salt/hash parece inválido: {linha_strip}. Marcando como inválido.")
                                    linha_adm_invalida_encontrada = True
                            else:
                                # Formato incompleto (não tem user;salt;hash;role)
                                print(f"AVISO: Usuário ADM encontrado na linha {numero_linha+1}, mas formato incompleto (partes={len(parts)}): {linha_strip}. Marcando como inválido.")
                                linha_adm_invalida_encontrada = True
                        else:
                            # É uma linha de outro usuário, assume-se válida por enquanto ou adiciona a validação aqui se necessário
                             linhas_validas.append(linha_strip) # Guarda linhas válidas de outros usuários

                    except Exception as e_parse:
                        # Erro ao processar uma linha específica
                        print(f"AVISO: Erro ao processar linha {numero_linha+1} do arquivo de usuários: {linha_strip}. Erro: {e_parse}")
                        messagebox.showwarning("Aviso Formato Usuário",
                                               f"Linha mal formada ou erro ao processar no arquivo {USUARIOS_FILE_NAME}:\n"
                                               f"'{linha_strip}'\nErro: {e_parse}\nIgnorando esta linha.", parent=None)

        except IOError as e_io:
            print(f"ERRO: Erro de leitura/escrita ao acessar {USUARIOS_FILE_PATH}: {e_io}")
            messagebox.showerror("Erro de Arquivo", f"Não foi possível ler o arquivo de usuários:\n{e_io}")
            return False
        except Exception as e_gen:
            print(f"ERRO: Erro inesperado ao processar o arquivo de usuários: {e_gen}")
            messagebox.showerror("Erro Inesperado", f"Ocorreu um erro inesperado ao verificar o arquivo de usuários:\n{e_gen}")
            return False

    # Passo 3: Se o ADM válido não foi encontrado, adicioná-lo
    #    (Nota: A abordagem ideal se encontrasse um ADM inválido seria
    #     reescrever o arquivo apenas com as linhas válidas + o novo ADM,
    #     mas aqui vamos apenas adicionar se nenhum válido foi encontrado)
    if not usuario_adm_encontrado_valido:
        if linha_adm_invalida_encontrada:
             print(f"INFO: Usuário ADM foi encontrado, mas em formato inválido. Adicionando ADM padrão novamente.")
        else:
             print(f"INFO: Usuário ADM padrão não encontrado ou arquivo inexistente. Criando/adicionando ADM...")

        try:
            # Gera o hash e salt para a senha padrão do ADM
            salt_adm_hex, hash_adm_hex = hash_password(DEFAULT_ADMIN_PASS)

            # Verifica se o hashing funcionou
            if salt_adm_hex and hash_adm_hex:
                # Abre o arquivo em modo 'append' (adicionar ao final)
                with open(USUARIOS_FILE_PATH, 'a', encoding='utf-8') as file_append:
                    # Cria a linha no formato correto
                    linha_adm_nova = f"{DEFAULT_ADMIN_USER};{salt_adm_hex};{hash_adm_hex};{ADMIN_ROLE}\n"
                    # Escreve a linha no arquivo
                    file_append.write(linha_adm_nova)
                    print(f"INFO: Usuário ADM padrão adicionado com sucesso ao arquivo.")
                    # Após adicionar, consideramos que o arquivo está 'ok'
                    return True
            else:
                # Se falhou ao gerar o hash/salt do ADM, é um erro crítico
                print("ERRO CRÍTICO: Falha ao gerar hash e salt para o usuário ADM padrão.")
                messagebox.showerror("Erro Crítico de Hashing",
                                     "Não foi possível gerar a senha segura para o usuário administrador padrão.\n"
                                     "O sistema não pode continuar.")
                return False # Falha crítica

        except IOError as e_io_write:
            print(f"ERRO CRÍTICO: Erro de leitura/escrita ao tentar adicionar ADM em {USUARIOS_FILE_PATH}: {e_io_write}")
            messagebox.showerror("Erro Crítico de Arquivo", f"Não foi possível escrever no arquivo de usuários:\n{e_io_write}")
            return False
        except Exception as e_gen_write:
            print(f"ERRO CRÍTICO: Erro inesperado ao tentar adicionar ADM: {e_gen_write}")
            messagebox.showerror("Erro Crítico Inesperado", f"Ocorreu um erro inesperado ao adicionar o usuário ADM:\n{e_gen_write}")
            return False
    else:
        # Se o ADM válido já foi encontrado, está tudo certo
        print("INFO: Verificação do arquivo de usuários concluída. ADM válido encontrado.")
        return True

def validar_cpf_completo(cpf_string):
    """
    Valida um número de CPF brasileiro, incluindo formato e dígitos verificadores.

    Args:
        cpf_string (str): O CPF como string, pode conter pontos ou traços.

    Returns:
        bool: True se o CPF for válido, False caso contrário.
    """
    # Passo 1: Limpar o CPF, mantendo apenas os dígitos
    cpf_numeros = ''.join(filter(str.isdigit, cpf_string))
    print(f"DEBUG CPF: Original='{cpf_string}', Limpo='{cpf_numeros}'")

    # Passo 2: Verificar se o CPF limpo tem exatamente 11 dígitos
    if len(cpf_numeros) != 11:
        print("DEBUG CPF: Falhou - não tem 11 dígitos.")
        return False

    # Passo 3: Verificar se todos os 11 dígitos são iguais (ex: "111.111.111-11")
    # Cria um conjunto (set) com os dígitos. Se o tamanho for 1, todos são iguais.
    if len(set(cpf_numeros)) == 1:
        print("DEBUG CPF: Falhou - todos os dígitos são iguais.")
        return False

    # Passo 4: Calcular o primeiro dígito verificador (DV1)
    try:
        soma_dv1 = 0
        multiplicador_dv1 = 10
        # Loop pelos primeiros 9 dígitos do CPF
        for i in range(9):
            digito = int(cpf_numeros[i])
            produto = digito * multiplicador_dv1
            soma_dv1 = soma_dv1 + produto
            multiplicador_dv1 = multiplicador_dv1 - 1 # Decrementa o multiplicador

        # Calcula o resto da divisão da soma por 11
        resto_dv1 = soma_dv1 % 11

        # Determina o valor esperado para o DV1
        dv1_calculado = 0 if resto_dv1 < 2 else 11 - resto_dv1

        # Compara o DV1 calculado com o 10º dígito do CPF fornecido
        dv1_fornecido = int(cpf_numeros[9])
        if dv1_calculado != dv1_fornecido:
            print(f"DEBUG CPF: Falhou - DV1 calculado ({dv1_calculado}) != DV1 fornecido ({dv1_fornecido}).")
            return False
        # else:
            # print(f"DEBUG CPF: DV1 OK ({dv1_calculado}).")

    except (ValueError, IndexError) as e:
        # Erro se algum caractere não for dígito ou se o índice estiver fora do range
        print(f"ERRO CPF: Erro ao calcular DV1 ({type(e).__name__}: {e}). CPF='{cpf_numeros}'")
        return False

    # Passo 5: Calcular o segundo dígito verificador (DV2)
    try:
        soma_dv2 = 0
        multiplicador_dv2 = 11
        # Loop pelos primeiros 10 dígitos do CPF (incluindo o DV1)
        for i in range(10):
            digito = int(cpf_numeros[i])
            produto = digito * multiplicador_dv2
            soma_dv2 = soma_dv2 + produto
            # print(f"DEBUG CPF DV2: digito={digito}, mult={multiplicador_dv2}, produto={produto}, soma={soma_dv2}")
            multiplicador_dv2 = multiplicador_dv2 - 1 # Decrementa o multiplicador

        # Calcula o resto da divisão da soma por 11
        resto_dv2 = soma_dv2 % 11

        # Determina o valor esperado para o DV2
        dv2_calculado = 0 if resto_dv2 < 2 else 11 - resto_dv2

        # Compara o DV2 calculado com o 11º dígito do CPF fornecido
        dv2_fornecido = int(cpf_numeros[10])
        if dv2_calculado != dv2_fornecido:
            print(f"DEBUG CPF: Falhou - DV2 calculado ({dv2_calculado}) != DV2 fornecido ({dv2_fornecido}).")
            return False
        # else:
            # print(f"DEBUG CPF: DV2 OK ({dv2_calculado}).")

    except (ValueError, IndexError) as e:
        # Erro se algum caractere não for dígito ou se o índice estiver fora do range
        print(f"ERRO CPF: Erro ao calcular DV2 ({type(e).__name__}: {e}). CPF='{cpf_numeros}'")
        return False

    # Passo 6: Se passou por todas as verificações, o CPF é válido
    print("DEBUG CPF: Válido.")
    return True

# --- Funções de Manipulação de Dados de Registro (Salvar, Buscar, Carregar, Excluir) ---

def salvar_dados_individual(tipo_registro, dados_dict):
    """
    Salva os dados de um registro em DOIS arquivos: um .txt e um .csv.

    Os arquivos são salvos em subpastas específicas (TXT e CSV) dentro
    da pasta da categoria do registro (Aluno, Funcionário, Professor).
    O nome base do arquivo é gerado a partir do nome sanitizado e do CPF numérico.
    Se os arquivos já existirem, serão sobrescritos (modo 'w').

    Args:
        tipo_registro (str): O tipo do registro ("Aluno", "Funcionário", "Professor").
        dados_dict (dict): Um dicionário contendo os dados do registro.
                           Espera-se que contenha chaves correspondentes a CAMPOS_CADASTRO.

    Returns:
        bool: True se ambos os arquivos (TXT e CSV) foram salvos com sucesso, False caso contrário.
    """
    print(f"INFO (Salvar): Iniciando salvamento para registro tipo '{tipo_registro}'.")

    # Passo 1: Validar tipo de registro e obter pasta da categoria
    subfolder_map = {
        "Aluno": SUBFOLDER_ALUNOS,
        "Funcionário": SUBFOLDER_FUNCIONARIOS,
        "Professor": SUBFOLDER_PROFESSORES
    }
    categoria_subfolder_name = subfolder_map.get(tipo_registro)
    if not categoria_subfolder_name:
        # Tipo de registro inválido
        messagebox.showerror("Erro Interno Grave", f"Tipo de registro desconhecido fornecido para salvar: '{tipo_registro}'.")
        print(f"ERRO (Salvar): Tipo de registro desconhecido: {tipo_registro}")
        return False

    # Passo 2: Construir caminhos base e garantir que as pastas existam
    # Caminho para a pasta da categoria (ex: .../Registros/Alunos)
    categoria_path = os.path.join(APP_FOLDER_PATH, categoria_subfolder_name)
    # Caminho para a subpasta TXT (ex: .../Registros/Alunos/TXT)
    txt_subfolder_path = os.path.join(categoria_path, SUBFOLDER_TXT)
    # Caminho para a subpasta CSV (ex: .../Registros/Alunos/CSV)
    csv_subfolder_path = os.path.join(categoria_path, SUBFOLDER_CSV)

    try:
        # Garante que a pasta principal exista (redundante se já chamado antes, mas seguro)
        if not verificar_pasta_principal(): return False
        # Cria a pasta da categoria se não existir (ex: Alunos)
        os.makedirs(categoria_path, exist_ok=True)
        # Cria a subpasta TXT se não existir
        os.makedirs(txt_subfolder_path, exist_ok=True)
        # Cria a subpasta CSV se não existir
        os.makedirs(csv_subfolder_path, exist_ok=True)
        print(f"DEBUG (Salvar): Pastas garantidas/criadas para '{tipo_registro}':")
        print(f"  - Categoria: {categoria_path}")
        print(f"  - TXT: {txt_subfolder_path}")
        print(f"  - CSV: {csv_subfolder_path}")
    except OSError as e:
        # Erro ao criar alguma das pastas
        messagebox.showerror("Erro de Diretório", f"Erro ao criar estrutura de pastas para '{tipo_registro}':\n{e}")
        print(f"ERRO (Salvar): Falha ao criar diretórios para {tipo_registro}. Erro: {e}")
        return False
    except Exception as e_dir:
        messagebox.showerror("Erro Inesperado de Diretório", f"Erro inesperado ao criar pastas:\n{e_dir}")
        print(f"ERRO (Salvar): Erro inesperado ao criar diretórios. Erro: {e_dir}")
        return False


    # Passo 3: Preparar nome do arquivo e caminhos completos
    # Pega o nome e CPF do dicionário (com valores padrão se não existirem)
    nome_registro = dados_dict.get("Nome", "Nome_Desconhecido")
    cpf_registro = dados_dict.get("CPF", "Sem_CPF")

    # Limpa o CPF para usar apenas números no nome do arquivo
    cpf_numeros = ''.join(filter(str.isdigit, cpf_registro))
    # Sanitiza o nome para usar no nome do arquivo
    nome_sanitizado = sanitize_filename(nome_registro)

    # Cria o nome base do arquivo (sem extensão)
    base_file_name = f"{nome_sanitizado}_{cpf_numeros}"
    print(f"DEBUG (Salvar): Nome base do arquivo gerado: '{base_file_name}'")

    # Monta o caminho completo para o arquivo TXT
    txt_file_path = os.path.join(txt_subfolder_path, base_file_name + FILE_EXTENSION_TXT)
    # Monta o caminho completo para o arquivo CSV
    csv_file_path = os.path.join(csv_subfolder_path, base_file_name + FILE_EXTENSION_CSV)
    print(f"DEBUG (Salvar): Caminho TXT: {txt_file_path}")
    print(f"DEBUG (Salvar): Caminho CSV: {csv_file_path}")

    # Garante que o campo 'TipoRegistro' esteja presente no dicionário antes de salvar
    if "TipoRegistro" not in dados_dict:
        dados_dict["TipoRegistro"] = tipo_registro

    # Flag para controlar sucesso geral
    sucesso_txt = False
    sucesso_csv = False

    # Passo 4: Salvar o arquivo TXT
    try:
        print(f"INFO (Salvar): Tentando salvar arquivo TXT em: {txt_file_path}")
        # Abre o arquivo TXT para escrita ('w' sobrescreve se existir)
        with open(txt_file_path, 'w', encoding='utf-8') as f_txt:
            # Itera sobre a ordem definida em CAMPOS_CADASTRO
            for campo in CAMPOS_CADASTRO:
                # Pega o valor do dicionário, ou string vazia se não existir
                valor_campo = dados_dict.get(campo, "")
                # Escreve a linha no formato "Campo: Valor"
                f_txt.write(f"{campo}: {valor_campo}\n")
        print(f"INFO (Salvar): Arquivo TXT salvo com sucesso.")
        sucesso_txt = True
    except IOError as e_io_txt:
        messagebox.showerror("Erro ao Salvar TXT", f"Erro ao salvar arquivo de texto:\n{txt_file_path}\n\nErro: {e_io_txt}")
        print(f"ERRO (Salvar): Falha ao salvar TXT. Erro: {e_io_txt}")
    except Exception as e_txt:
        messagebox.showerror("Erro Inesperado ao Salvar TXT", f"Erro desconhecido ao salvar arquivo de texto:\n{e_txt}")
        print(f"ERRO (Salvar): Erro inesperado ao salvar TXT. Erro: {e_txt}")

    # Passo 5: Salvar o arquivo CSV
    try:
        print(f"INFO (Salvar): Tentando salvar arquivo CSV em: {csv_file_path}")
        # Abre o arquivo CSV para escrita ('w' sobrescreve, newline='' é importante)
        with open(csv_file_path, 'w', encoding='utf-8', newline='') as f_csv:
            # Define os nomes das colunas (cabeçalho) usando a ordem de CAMPOS_CADASTRO
            fieldnames = CAMPOS_CADASTRO
            # Cria um objeto DictWriter, que mapeia dicionários para linhas CSV
            writer = csv.DictWriter(f_csv, fieldnames=fieldnames)

            # Escreve a linha de cabeçalho no arquivo CSV
            writer.writeheader()
            # Escreve a linha de dados, usando o dicionário 'dados_dict'
            # O DictWriter pegará os valores das chaves que correspondem aos fieldnames
            writer.writerow(dados_dict)
        print(f"INFO (Salvar): Arquivo CSV salvo com sucesso.")
        sucesso_csv = True
    except IOError as e_io_csv:
        messagebox.showerror("Erro ao Salvar CSV", f"Erro ao salvar arquivo CSV:\n{csv_file_path}\n\nErro: {e_io_csv}")
        print(f"ERRO (Salvar): Falha ao salvar CSV. Erro: {e_io_csv}")
    except Exception as e_csv:
        messagebox.showerror("Erro Inesperado ao Salvar CSV", f"Erro desconhecido ao salvar arquivo CSV:\n{e_csv}")
        print(f"ERRO (Salvar): Erro inesperado ao salvar CSV. Erro: {e_csv}")

    # Passo 6: Retornar sucesso geral
    if sucesso_txt and sucesso_csv:
        print(f"INFO (Salvar): Ambos os arquivos TXT e CSV foram salvos com sucesso para '{base_file_name}'.")
        return True
    else:
        print(f"ERRO (Salvar): Falha ao salvar um ou ambos os arquivos (TXT: {sucesso_txt}, CSV: {sucesso_csv}).")
        # Mensagens de erro específicas já foram mostradas
        return False


def find_record_file_by_cpf(cpf_to_find):
    """
    Busca o arquivo de registro .TXT exato pelo CPF fornecido.

    Procura em todas as subpastas de categoria (Alunos, Funcionários, Professores)
    e dentro de suas respectivas subpastas TXT. O nome do arquivo deve terminar
    com '_CPFnumerico.txt'.

    Args:
        cpf_to_find (str): O CPF a ser buscado (pode conter pontos/traços).

    Returns:
        tuple: (caminho_completo_txt, tipo_registro) se encontrado.
               (None, None) se não encontrado ou se o CPF for inválido.
    """
    print(f"DEBUG (Find): Buscando registro TXT para CPF: '{cpf_to_find}'")

    # Passo 1: Limpar e validar o formato básico do CPF
    cpf_numeros = ''.join(filter(str.isdigit, cpf_to_find))
    # Verifica se tem 11 dígitos após limpeza
    if len(cpf_numeros) != 11:
        print(f"INFO (Find): CPF fornecido ({cpf_to_find} -> {cpf_numeros}) não tem 11 dígitos. Busca cancelada.")
        # Não mostra messagebox aqui, a função chamadora pode decidir
        return None, None # Formato inválido para busca

    # Passo 2: Definir as pastas de categoria e tipos correspondentes
    pastas_tipos_map = {
        SUBFOLDER_ALUNOS: "Aluno",
        SUBFOLDER_FUNCIONARIOS: "Funcionário",
        SUBFOLDER_PROFESSORES: "Professor"
    }

    # Passo 3: Iterar sobre cada categoria para buscar o arquivo
    for categoria_folder_name, record_type in pastas_tipos_map.items():
        # Monta o caminho para a subpasta TXT dentro da categoria
        # Ex: .../Registros/Alunos/TXT
        txt_subfolder_path = os.path.join(APP_FOLDER_PATH, categoria_folder_name, SUBFOLDER_TXT)
        print(f"DEBUG (Find): Verificando pasta: {txt_subfolder_path}")

        # Verifica se esta pasta TXT realmente existe
        if not os.path.isdir(txt_subfolder_path):
            print(f"DEBUG (Find): Pasta TXT '{txt_subfolder_path}' não existe. Pulando.")
            continue # Pula para a próxima categoria se a pasta TXT não existe

        # Tenta listar os arquivos dentro da pasta TXT
        try:
            arquivos_na_pasta_txt = os.listdir(txt_subfolder_path)
            print(f"DEBUG (Find): Encontrados {len(arquivos_na_pasta_txt)} itens em {txt_subfolder_path}")

            # Constrói o sufixo esperado para o nome do arquivo
            # Ex: _12345678900.txt
            expected_suffix = f"_{cpf_numeros}{FILE_EXTENSION_TXT}"

            # Itera sobre os arquivos encontrados na pasta TXT
            for filename in arquivos_na_pasta_txt:
                # Verifica se o nome do arquivo termina com o sufixo esperado
                if filename.endswith(expected_suffix):
                    # ENCONTROU!
                    arquivo_encontrado_path = os.path.join(txt_subfolder_path, filename)
                    print(f"INFO (Find): Arquivo encontrado para CPF {cpf_numeros}: {arquivo_encontrado_path}")
                    # Retorna o caminho completo do arquivo TXT e o tipo de registro
                    return arquivo_encontrado_path, record_type

        except OSError as e:
            # Erro ao tentar listar arquivos (ex: permissão)
            print(f"AVISO (Find): Erro ao ler diretório '{txt_subfolder_path}': {e}. Pulando esta pasta.")
            # Não mostra messagebox para não ser intrusivo
            continue # Pula para a próxima categoria
        except Exception as e_list:
             print(f"ERRO (Find): Erro inesperado ao listar diretório '{txt_subfolder_path}': {e_list}. Pulando esta pasta.")
             continue # Pula para a próxima categoria

    # Passo 4: Se o loop terminou sem encontrar o arquivo em nenhuma categoria
    print(f"INFO (Find): Nenhum arquivo TXT encontrado para o CPF {cpf_numeros} em nenhuma categoria.")
    return None, None # Não encontrado

def load_record_data(file_path_txt):
    """
    Carrega os dados de um arquivo de registro individual .txt (formato Chave: Valor).

    Args:
        file_path_txt (str): O caminho completo para o arquivo .txt a ser carregado
                             (geralmente obtido de `find_record_file_by_cpf`).

    Returns:
        dict: Um dicionário com os dados carregados (chaves são os nomes dos campos).
              Retorna um dicionário vazio se o arquivo não for encontrado.
              Retorna None em caso de erro de leitura ou formato.
    """
    print(f"DEBUG (Load): Tentando carregar dados do arquivo TXT: {file_path_txt}")
    # Dicionário para armazenar os dados lidos
    record_data = {}
    try:
        # Abre o arquivo .txt especificado para leitura
        with open(file_path_txt, 'r', encoding='utf-8') as f:
            # Processa cada linha do arquivo
            for numero_linha, line in enumerate(f):
                linha_strip = line.strip() # Remove espaços/quebras de linha extras

                # Verifica se a linha contém um separador ':'
                if ':' in linha_strip:
                    try:
                        # Tenta dividir a linha em chave e valor no primeiro ':' encontrado
                        key, value = linha_strip.split(':', 1)
                        # Remove espaços extras da chave e do valor e armazena no dicionário
                        chave_limpa = key.strip()
                        valor_limpo = value.strip()
                        record_data[chave_limpa] = valor_limpo
                        # print(f"DEBUG (Load): Linha {numero_linha+1}: Chave='{chave_limpa}', Valor='{valor_limpo}'")
                    except ValueError:
                        # Se split falhar por algum motivo inesperado (não deveria acontecer se ':' está presente)
                         print(f"AVISO (Load): Linha {numero_linha+1} mal formatada (erro no split?) em {file_path_txt}: '{linha_strip}'")
                elif linha_strip: # Se a linha não está vazia mas não tem ':'
                     print(f"AVISO (Load): Linha {numero_linha+1} sem separador ':' ignorada em {file_path_txt}: '{linha_strip}'")

        # Se chegou aqui, a leitura (pelo menos parcial) foi bem-sucedida
        print(f"INFO (Load): Dados carregados com sucesso de {file_path_txt}. {len(record_data)} campos lidos.")
        return record_data

    except FileNotFoundError:
        # Se o arquivo .txt não foi encontrado no caminho especificado
        print(f"ERRO (Load): Arquivo de registro TXT não encontrado: {file_path_txt}")
        # Retorna dicionário vazio para indicar 'não encontrado' de forma não-errônea
        # A função chamadora pode decidir mostrar erro se um arquivo era esperado.
        return {} # Alterado de None para {} para consistência em alguns usos
    except IOError as e:
        # Erro durante a leitura do arquivo (ex: permissão negada)
        print(f"ERRO (Load): Erro de IO ao ler arquivo de registro TXT: {file_path_txt}\n{e}")
        messagebox.showerror("Erro de Leitura", f"Erro ao ler arquivo de registro:\n{file_path_txt}\n{e}", parent=None)
        return None # Indica um erro real de leitura
    except Exception as e_parse:
        # Outro erro inesperado durante o processamento do arquivo
        print(f"ERRO (Load): Erro inesperado ao processar formato do arquivo TXT: {file_path_txt}\n{e_parse}")
        messagebox.showerror("Erro de Formato", f"Erro ao processar arquivo de registro:\n{file_path_txt}\n{e_parse}", parent=None)
        return None # Indica um erro real de processamento

def _get_associated_csv_path(txt_file_path):
    """
    Função auxiliar para obter o caminho do arquivo CSV correspondente a um arquivo TXT.

    Assume a estrutura .../Categoria/TXT/arquivo.txt -> .../Categoria/CSV/arquivo.csv

    Args:
        txt_file_path (str): O caminho completo para o arquivo .txt.

    Returns:
        str: O caminho completo esperado para o arquivo .csv correspondente, ou None se o
             caminho TXT não parecer estar na estrutura esperada.
    """
    try:
        # Pega o nome do arquivo TXT (ex: Nome_123.txt)
        txt_filename = os.path.basename(txt_file_path)
        # Pega o diretório onde o TXT está (ex: .../Registros/Alunos/TXT)
        txt_dirname = os.path.dirname(txt_file_path)

        # Verifica se a pasta pai do TXT é chamada SUBFOLDER_TXT
        if os.path.basename(txt_dirname) != SUBFOLDER_TXT:
            print(f"ERRO (Aux CSV Path): Pasta pai do TXT não é '{SUBFOLDER_TXT}': {txt_dirname}")
            return None

        # Pega o diretório da categoria (ex: .../Registros/Alunos)
        categoria_dirname = os.path.dirname(txt_dirname)

        # Monta o caminho para a pasta CSV (ex: .../Registros/Alunos/CSV)
        csv_dirname = os.path.join(categoria_dirname, SUBFOLDER_CSV)

        # Monta o nome do arquivo CSV (troca extensão .txt por .csv)
        csv_filename = os.path.splitext(txt_filename)[0] + FILE_EXTENSION_CSV

        # Monta o caminho completo para o arquivo CSV
        csv_file_path = os.path.join(csv_dirname, csv_filename)
        # print(f"DEBUG (Aux CSV Path): TXT='{txt_file_path}' -> CSV='{csv_file_path}'")
        return csv_file_path

    except Exception as e:
        print(f"ERRO (Aux CSV Path): Erro inesperado ao derivar caminho CSV de '{txt_file_path}': {e}")
        return None

# --- Janela de Edição ---

def janela_edicao(original_txt_file_path, record_type, initial_data):
    """
    Cria e exibe a janela para editar um registro existente.
    Os dados são carregados do dicionário `initial_data`.
    Ao salvar, chama `salvar_dados_individual` que sobrescreverá
    os arquivos TXT e CSV correspondentes.

    Args:
        original_txt_file_path (str): Caminho para o arquivo TXT original (usado para referência, não editado diretamente aqui).
        record_type (str): O tipo de registro ("Aluno", etc.).
        initial_data (dict): Dicionário com os dados atuais do registro a serem pré-preenchidos.
    """
    edit_window = tk.Toplevel()
    edit_window.title(f"Editar Registro - {record_type}")
    # edit_window.geometry("500x550") # Tamanho pode ser ajustado

    # Dicionário para guardar as variáveis Tkinter (StringVar, BooleanVar)
    # que serão vinculadas aos campos de entrada (widgets)
    vars_dict = {}

    # Lista de atividades possíveis (poderia ser carregada de um arquivo de configuração)
    lista_possiveis_atividades = ["Musculação", "CrossFit", "Natação", "Dança", "Funcional", "Pilates", "Yoga"]

    # --- Preenchimento Inicial dos Campos ---
    # Itera sobre todos os campos definidos em CAMPOS_CADASTRO
    print("DEBUG (Edição): Preenchendo variáveis iniciais...")
    for campo in CAMPOS_CADASTRO:
        # Pega o valor atual para este campo do dicionário `initial_data`
        # Se o campo não existir no dicionário, usa uma string vazia "" como padrão
        valor_inicial = initial_data.get(campo, "")
        # print(f"  - Campo: {campo}, Valor Inicial: '{valor_inicial}'")

        # Tratamento especial para campos específicos
        if campo == "Atividades":
            # Atividades são representadas por Checkbuttons, então precisamos de BooleanVars
            # Pega a string de atividades (ex: "Natação, Yoga") e divide em uma lista
            # Remove espaços em branco e ignora itens vazios
            atividades_atuais_lista = []
            if valor_inicial: # Só processa se não for vazio
                 partes = valor_inicial.split(',')
                 for parte in partes:
                      parte_limpa = parte.strip()
                      if parte_limpa: # Adiciona só se não for vazio após limpar
                           atividades_atuais_lista.append(parte_limpa)

            # Cria um sub-dicionário dentro de vars_dict para guardar as BooleanVars das atividades
            vars_dict[campo] = {}
            # Para cada atividade possível...
            for atividade_possivel in lista_possiveis_atividades:
                # Cria uma BooleanVar. Define como True se a atividade_possivel está na lista de atividades atuais, False caso contrário.
                esta_marcado = (atividade_possivel in atividades_atuais_lista)
                vars_dict[campo][atividade_possivel] = tk.BooleanVar(value=esta_marcado)
                # print(f"    - Atividade: {atividade_possivel}, Marcado: {esta_marcado}")

        elif campo == "Observação":
            # Observação usa um widget tk.Text, que não se vincula bem a StringVar para multilinhas.
            # O valor será pego diretamente do widget Text ao salvar.
            # Então, não criamos uma Var aqui, mas guardamos o valor inicial para usar depois.
            valor_inicial_observacao = valor_inicial # Guarda para usar no insert() do Text widget
            pass # Nenhuma Var criada em vars_dict

        elif campo in ["CPF", "TipoRegistro"]:
            # CPF e Tipo de Registro não devem ser editados pelo usuário nesta janela.
            # Criamos StringVars para eles poderem ser exibidos, mas os widgets serão 'readonly'.
            vars_dict[campo] = tk.StringVar(value=valor_inicial)

        else:
            # Para os demais campos (Nome, Endereço, Cidade, Estado, E-mail, Sexo),
            # criamos StringVars normais, vinculadas aos widgets Entry ou Combobox/Radiobutton.
            vars_dict[campo] = tk.StringVar(value=valor_inicial)

    # --- Função Interna para Salvar ---
    def _funcao_interna_salvar_alteracoes():
        """
        Função chamada quando o botão 'Salvar Alterações' é clicado.
        Coleta os dados dos widgets da janela, valida e chama a função
        principal `salvar_dados_individual`.
        """
        print("DEBUG (Edição): Botão Salvar clicado. Coletando dados...")

        # Dicionário para guardar os dados atualizados coletados da interface
        dados_atualizados = {}

        # Passo 1: Coletar dados dos campos de texto (StringVars)
        # Itera sobre os itens no dicionário de variáveis
        for campo, tk_var in vars_dict.items():
             # Verifica se é uma StringVar (ignora o sub-dicionário de BooleanVars de Atividades)
             # E verifica se NÃO é CPF ou TipoRegistro (que não foram editados)
             if isinstance(tk_var, tk.StringVar) and campo not in ["CPF", "TipoRegistro"]:
                 # Pega o valor atual da StringVar, remove espaços extras e guarda
                 valor_atual = tk_var.get().strip()
                 dados_atualizados[campo] = valor_atual
                 # print(f"  - Coletado (StringVar): {campo} = '{valor_atual}'")

        # Passo 2: Coletar dados das Atividades (BooleanVars)
        atividades_selecionadas_lista = []
        # Verifica se a chave 'Atividades' (que contém o sub-dicionário) existe
        if "Atividades" in vars_dict:
            # Itera sobre cada atividade e sua respectiva BooleanVar
            for nome_atividade, var_booleana in vars_dict["Atividades"].items():
                # Se a BooleanVar estiver marcada (True)...
                if var_booleana.get():
                    # Adiciona o nome da atividade à lista
                    atividades_selecionadas_lista.append(nome_atividade)
                    # print(f"  - Coletado (Atividade): {nome_atividade} = True")
        # Junta a lista de atividades selecionadas em uma única string separada por vírgula
        dados_atualizados["Atividades"] = ", ".join(atividades_selecionadas_lista)
        # print(f"  - Coletado (Atividades String): '{dados_atualizados['Atividades']}'")

        # Passo 3: Coletar dados da Observação (direto do widget Text)
        # Pega todo o texto do widget 'observacao_entry' desde o início ("1.0") até o fim (tk.END)
        # e remove espaços/quebras de linha extras do início/fim.
        dados_atualizados["Observação"] = observacao_entry.get("1.0", tk.END).strip()
        # print(f"  - Coletado (Observação): '{dados_atualizados['Observação'][:50]}...'") # Mostra só o início

        # Passo 4: Adicionar CPF e TipoRegistro (que não foram editados) de volta aos dados
        # Pega o CPF original dos dados iniciais (não da interface)
        dados_atualizados["CPF"] = initial_data.get("CPF", "")
        # Pega o Tipo de Registro original (passado como argumento para a janela)
        dados_atualizados["TipoRegistro"] = record_type
        # print(f"  - Adicionado (Não editável): CPF='{dados_atualizados['CPF']}', Tipo='{dados_atualizados['TipoRegistro']}'")

        # Passo 5: Validação dos dados coletados
        print("DEBUG (Edição): Validando dados coletados...")
        # Define quais campos são obrigatórios para edição (CPF/Tipo já existem)
        campos_obrigatorios_edicao = ["Nome", "Endereço", "Cidade", "Estado", "E-mail", "Sexo"]
        # Cria uma lista de campos obrigatórios que estão vazios nos dados atualizados
        campos_faltando_lista = []
        for campo_obrigatorio in campos_obrigatorios_edicao:
             if not dados_atualizados.get(campo_obrigatorio): # .get() retorna None se não existir ou "" se existir mas for vazio
                  campos_faltando_lista.append(campo_obrigatorio)

        # Se a lista de campos faltando não está vazia, mostra erro e para
        if campos_faltando_lista:
            campos_faltando_str = ", ".join(campos_faltando_lista)
            messagebox.showerror("Erro de Validação",
                                 f"Por favor, preencha os campos obrigatórios:\n{campos_faltando_str}",
                                 parent=edit_window) # Mostra o erro na janela de edição
            print(f"ERRO (Edição): Validação falhou - Campos obrigatórios faltando: {campos_faltando_str}")
            return # Interrompe o processo de salvar

        # Validação simples de E-mail (verifica se contém '@')
        email_digitado = dados_atualizados.get("E-mail", "")
        if "@" not in email_digitado:
             messagebox.showerror("Erro de Validação", "O formato do E-mail parece inválido (falta '@').", parent=edit_window)
             print("ERRO (Edição): Validação falhou - E-mail sem '@'.")
             email_entry.focus_set() # Coloca o foco de volta no campo de email
             return # Interrompe o processo de salvar

        # Se passou por todas as validações...
        print("DEBUG (Edição): Validação OK.")

        # Passo 6: Confirmação final com o usuário
        if messagebox.askyesno("Confirmar Alterações",
                               "Tem certeza que deseja salvar as alterações neste registro?\n"
                               "(Os arquivos TXT e CSV existentes serão sobrescritos)",
                               parent=edit_window):
            # Se o usuário clicou 'Sim'...
            print("INFO (Edição): Usuário confirmou. Tentando salvar...")
            # Chama a função principal de salvamento, passando o tipo e os dados atualizados
            sucesso_salvar = salvar_dados_individual(record_type, dados_atualizados)

            # Verifica se o salvamento foi bem-sucedido
            if sucesso_salvar:
                messagebox.showinfo("Sucesso", "Registro alterado com sucesso!", parent=edit_window)
                print("INFO (Edição): Salvamento concluído com sucesso. Fechando janela.")
                edit_window.destroy() # Fecha a janela de edição
            else:
                # Se salvar_dados_individual retornou False, ela já deve ter mostrado uma mensagem de erro.
                print("ERRO (Edição): A função salvar_dados_individual() retornou erro.")
                # Não precisa mostrar outra mensagem aqui.
        else:
            # Se o usuário clicou 'Não' na confirmação
            print("INFO (Edição): Usuário cancelou o salvamento.")
            # Não faz nada, a janela continua aberta.

    # --- Criação dos Widgets da Interface Gráfica ---
    print("DEBUG (Edição): Criando widgets da janela...")
    # Frame principal com padding para organizar os widgets
    main_frame = ttk.Frame(edit_window, padding="10")
    main_frame.pack(expand=True, fill=tk.BOTH) # Frame se expande com a janela

    # Layout em Grid: Linhas e Colunas para alinhar Labels e Entradas
    # Coluna 0: Labels (Textos descritivos)
    # Coluna 1: Widgets de entrada (Entry, Combobox, Radiobutton, Checkbutton, Text)
    # Coluna 2: Espaço para hints ou widgets menores

    row_num = 0 # Contador de linhas para o grid

    # Campo Tipo (Não editável)
    ttk.Label(main_frame, text="Tipo:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=3)
    ttk.Label(main_frame, text=record_type, font=('TkDefaultFont', 10, 'bold')).grid(row=row_num, column=1, columnspan=2, sticky=tk.W, padx=5, pady=3)
    row_num += 1

    # Campo CPF (Não editável)
    ttk.Label(main_frame, text="CPF:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=3)
    cpf_var_display = vars_dict.get("CPF", tk.StringVar(value="ERRO_CPF")) # Pega a var ou cria uma temporária
    cpf_entry_display = ttk.Entry(main_frame, textvariable=cpf_var_display, width=15, state='readonly') # state='readonly' impede edição
    cpf_entry_display.grid(row=row_num, column=1, padx=5, pady=3, sticky=tk.W)
    row_num += 1

    # Campo Nome (Editável)
    ttk.Label(main_frame, text="Nome*:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=3)
    nome_entry = ttk.Entry(main_frame, textvariable=vars_dict.get("Nome"), width=40)
    nome_entry.grid(row=row_num, column=1, columnspan=2, padx=5, pady=3, sticky=tk.EW) # EW = expande horizontalmente
    nome_entry.focus_set() # Coloca o foco inicial neste campo
    row_num += 1

    # Campo Endereço (Editável)
    ttk.Label(main_frame, text="Endereço*:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=3)
    endereco_entry = ttk.Entry(main_frame, textvariable=vars_dict.get("Endereço"), width=40)
    endereco_entry.grid(row=row_num, column=1, columnspan=2, padx=5, pady=3, sticky=tk.EW)
    row_num += 1

    # Campo Cidade (Editável)
    ttk.Label(main_frame, text="Cidade*:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=3)
    cidade_entry = ttk.Entry(main_frame, textvariable=vars_dict.get("Cidade"), width=30)
    cidade_entry.grid(row=row_num, column=1, padx=5, pady=3, sticky=tk.W) # W = alinha esquerda, não expande tanto
    row_num += 1

    # Campo Estado (Editável - Combobox)
    ttk.Label(main_frame, text="Estado*:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=3)
    lista_estados = ["AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"]
    estado_var_combo = vars_dict.get("Estado")
    # Garante que o valor inicial (vindo do arquivo) esteja na lista de estados. Se não estiver, seleciona o primeiro como padrão.
    if estado_var_combo and estado_var_combo.get() not in lista_estados:
        estado_var_combo.set(lista_estados[0] if lista_estados else "") # Define o primeiro estado ou vazio
    estado_combo = ttk.Combobox(main_frame, textvariable=estado_var_combo, values=lista_estados, state="readonly", width=5) # readonly impede digitar
    estado_combo.grid(row=row_num, column=1, padx=5, pady=3, sticky=tk.W)
    row_num += 1

    # Campo E-mail (Editável)
    ttk.Label(main_frame, text="E-mail*:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=3)
    email_entry = ttk.Entry(main_frame, textvariable=vars_dict.get("E-mail"), width=40)
    email_entry.grid(row=row_num, column=1, columnspan=2, padx=5, pady=3, sticky=tk.EW)
    row_num += 1

    # Campo Sexo (Editável - Radiobuttons)
    ttk.Label(main_frame, text="Sexo*:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=3)
    # Frame para agrupar os radio buttons horizontalmente
    sexo_frame = ttk.Frame(main_frame)
    sexo_frame.grid(row=row_num, column=1, columnspan=2, padx=5, pady=0, sticky=tk.W)
    sexo_var_radio = vars_dict.get("Sexo")
    # Garante que um valor válido esteja selecionado inicialmente
    if sexo_var_radio and sexo_var_radio.get() not in ["Masculino", "Feminino", "Outro"]:
         sexo_var_radio.set("Masculino") # Define um padrão se o valor carregado for inválido
    # Cria os Radiobuttons, todos vinculados à mesma variável 'sexo_var_radio'
    ttk.Radiobutton(sexo_frame, text="M", variable=sexo_var_radio, value="Masculino").pack(side=tk.LEFT, padx=(0, 5))
    ttk.Radiobutton(sexo_frame, text="F", variable=sexo_var_radio, value="Feminino").pack(side=tk.LEFT, padx=(0, 5))
    ttk.Radiobutton(sexo_frame, text="Outros", variable=sexo_var_radio, value="Outro").pack(side=tk.LEFT)
    row_num += 1

    # Campo Atividades (Editável - Checkbuttons)
    ttk.Label(main_frame, text="Atividades:").grid(row=row_num, column=0, sticky=tk.NW, padx=5, pady=5) # NW = Alinha no Noroeste (topo-esquerda)
    # Frame para agrupar os checkbuttons
    atividades_frame = ttk.Frame(main_frame)
    atividades_frame.grid(row=row_num, column=1, columnspan=2, padx=5, pady=3, sticky=tk.W)
    # Cria os checkbuttons dinamicamente, organizando em colunas
    coluna_atual_chk = 0
    linha_atual_chk = 0
    max_colunas_chk = 3 # Quantos checkbuttons por linha
    # Verifica se o dicionário de atividades foi criado corretamente
    if "Atividades" in vars_dict:
        # Itera sobre a lista de atividades possíveis
        for i, nome_atividade in enumerate(lista_possiveis_atividades):
            # Garante que a BooleanVar para esta atividade existe no dicionário
            if nome_atividade in vars_dict["Atividades"]:
                var_booleana_ativ = vars_dict["Atividades"][nome_atividade]
                # Cria o Checkbutton
                chk = ttk.Checkbutton(atividades_frame, text=nome_atividade, variable=var_booleana_ativ)
                # Posiciona no grid dentro do frame de atividades
                chk.grid(row=linha_atual_chk, column=coluna_atual_chk, sticky=tk.W, padx=2, pady=1)
                # Atualiza contadores de coluna/linha para o próximo checkbutton
                coluna_atual_chk += 1
                if coluna_atual_chk >= max_colunas_chk:
                    coluna_atual_chk = 0
                    linha_atual_chk += 1
    row_num += (linha_atual_chk + 1) # Atualiza o número da linha principal

    # Campo Observação (Editável - Text com Scrollbar)
    ttk.Label(main_frame, text="Observação:").grid(row=row_num, column=0, sticky=tk.NW, padx=5, pady=5)
    # Frame para conter o widget Text e a Scrollbar juntos
    obs_frame = ttk.Frame(main_frame)
    obs_frame.grid(row=row_num, column=1, columnspan=2, padx=5, pady=5, sticky=tk.NSEW) # NSEW = expande em todas as direções
    # Cria o widget Text
    observacao_entry = tk.Text(obs_frame, height=4, width=38, wrap=tk.WORD) # wrap=WORD quebra linha por palavra
    # Cria a Scrollbar vertical
    obs_scrollbar = ttk.Scrollbar(obs_frame, orient=tk.VERTICAL, command=observacao_entry.yview)
    # Vincula a scrollbar ao widget Text
    observacao_entry.config(yscrollcommand=obs_scrollbar.set)
    # Empacota o Text à esquerda e a Scrollbar à direita dentro do 'obs_frame'
    observacao_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True) # Text expande
    obs_scrollbar.pack(side=tk.RIGHT, fill=tk.Y) # Scrollbar preenche verticalmente
    # Insere o texto inicial (carregado do arquivo) no widget Text
    observacao_entry.insert("1.0", initial_data.get("Observação", "")) # Usa .get() para segurança
    row_num += 1

    # --- Botões de Ação ---
    # Frame para os botões Salvar e Cancelar
    botoes_frame = ttk.Frame(main_frame)
    # Coloca o frame de botões abaixo de tudo, abrangendo as colunas de Label e Widget
    botoes_frame.grid(row=row_num, column=0, columnspan=3, pady=15) # pady adiciona espaço vertical

    # Botão Salvar
    # Chama a função interna _funcao_interna_salvar_alteracoes quando clicado
    botao_salvar = ttk.Button(botoes_frame, text="Salvar Alterações", command=_funcao_interna_salvar_alteracoes)
    botao_salvar.pack(side=tk.LEFT, padx=10)

    # Botão Cancelar
    # Simplesmente fecha a janela de edição (edit_window.destroy)
    botao_cancelar = ttk.Button(botoes_frame, text="Cancelar", command=edit_window.destroy)
    botao_cancelar.pack(side=tk.LEFT, padx=10)
    row_num += 1

    # --- Configuração de Expansão da Janela ---
    # Faz com que a coluna 1 (onde estão os widgets de entrada) se expanda horizontalmente se a janela for redimensionada
    main_frame.grid_columnconfigure(1, weight=1)
    # Faz com que a linha do widget de Observação (que é a linha 9, mas usamos row_num-2 por segurança) se expanda verticalmente
    main_frame.grid_rowconfigure(row_num - 2, weight=1) # Linha da observação

    print("DEBUG (Edição): Widgets criados e janela pronta.")


# --- Função Coordenadora para Alterar Registro ---

def iniciar_alteracao_registro():
    """
    Pede o CPF ao usuário para iniciar o processo de alteração.
    Valida o CPF, localiza o arquivo .txt correspondente, carrega os dados
    e, se tudo estiver ok, abre a janela de edição (`janela_edicao`).
    """
    print("INFO (Alterar): Iniciando fluxo de alteração de registro.")
    # Passo 1: Pedir o CPF ao usuário
    cpf_alvo_str = simpledialog.askstring("Alterar Registro por CPF",
                                          "Digite o CPF (somente números ou com pontos/traço)\n"
                                          "do registro que deseja alterar:",
                                          parent=None) # Janela principal como pai implícito

    # Passo 2: Verificar se o usuário forneceu um CPF ou cancelou
    if not cpf_alvo_str:
        print("INFO (Alterar): Usuário cancelou a entrada do CPF.")
        return # Interrompe o fluxo

    print(f"INFO (Alterar): CPF fornecido pelo usuário: '{cpf_alvo_str}'")

    # Passo 3: Validar o CPF (formato e dígitos verificadores) usando a função completa
    if not validar_cpf_completo(cpf_alvo_str):
        # CPF inválido
        messagebox.showerror("CPF Inválido",
                             f"O CPF '{cpf_alvo_str}' parece ser inválido.\n"
                             "Por favor, verifique o número e os dígitos verificadores e tente novamente.",
                             parent=None)
        print(f"ERRO (Alterar): CPF '{cpf_alvo_str}' considerado inválido pela função validar_cpf_completo.")
        return # Interrompe o fluxo

    # Se chegou aqui, o CPF tem formato e dígitos válidos.
    print(f"INFO (Alterar): CPF '{cpf_alvo_str}' validado com sucesso.")

    # Passo 4: Buscar o arquivo .txt correspondente ao CPF validado
    # Limpa o CPF para busca (embora find_record_file_by_cpf também limpe)
    cpf_alvo_numeros = "".join(filter(str.isdigit, cpf_alvo_str))
    print(f"INFO (Alterar): Buscando arquivo TXT para CPF numérico: {cpf_alvo_numeros}")
    # Chama a função de busca (que agora procura na subpasta TXT)
    arquivo_txt_encontrado, tipo_registro_encontrado = find_record_file_by_cpf(cpf_alvo_numeros)

    # Passo 5: Verificar se o arquivo foi encontrado
    if not arquivo_txt_encontrado:
        # Se find_record_file_by_cpf retornou None para o caminho
        messagebox.showinfo("Registro Não Encontrado",
                            f"Nenhum registro foi encontrado para o CPF: {cpf_alvo_numeros}\n"
                            "Verifique se o CPF está correto ou se o registro existe.", parent=None)
        print(f"INFO (Alterar): Nenhum arquivo TXT encontrado para CPF {cpf_alvo_numeros}.")
        return # Interrompe o fluxo

    # Se chegou aqui, o arquivo TXT foi encontrado.
    print(f"INFO (Alterar): Arquivo TXT encontrado: {arquivo_txt_encontrado} (Tipo: {tipo_registro_encontrado})")

    # Passo 6: Carregar os dados do arquivo .txt encontrado
    print(f"INFO (Alterar): Carregando dados de '{arquivo_txt_encontrado}'...")
    dados_atuais_dict = load_record_data(arquivo_txt_encontrado)

    # Passo 7: Verificar se os dados foram carregados com sucesso
    # load_record_data retorna {} se não encontrado (já tratado acima) ou None se erro de leitura/formato
    if dados_atuais_dict is None:
        # Se houve erro ao carregar (a função load_record_data já deve ter mostrado um messagebox)
        print(f"ERRO (Alterar): Falha ao carregar dados de '{arquivo_txt_encontrado}'. Abortando alteração.")
        # Não precisa mostrar outra mensagem aqui.
        return # Interrompe o fluxo
    elif not dados_atuais_dict:
         # Se retornou dicionário vazio, significa que o arquivo foi encontrado mas estava vazio ou sem dados válidos.
         messagebox.showwarning("Arquivo Vazio ou Inválido",
                                f"O arquivo de registro encontrado para o CPF {cpf_alvo_numeros} está vazio ou não contém dados reconhecíveis.\n"
                                f"Não é possível editá-lo.", parent=None)
         print(f"AVISO (Alterar): Arquivo '{arquivo_txt_encontrado}' carregado, mas resultou em dicionário vazio.")
         return # Interrompe o fluxo


    # Se chegou aqui, os dados foram carregados com sucesso.
    print(f"INFO (Alterar): Dados carregados com sucesso. {len(dados_atuais_dict)} campos lidos.")

    # Passo 8: Abrir a janela de edição, passando os dados carregados
    print("INFO (Alterar): Abrindo a janela de edição...")
    janela_edicao(arquivo_txt_encontrado, tipo_registro_encontrado, dados_atuais_dict)
    print("INFO (Alterar): Janela de edição foi aberta.")


# --- Função para Excluir Registro ---

def excluir_cadastro_por_cpf(usuario_logado):
    """
    Pede o CPF, valida, localiza os arquivos (TXT e CSV), pede confirmação,
    verifica a senha do usuário logado e, se tudo ok, exclui ambos os arquivos.

    Args:
        usuario_logado (str): O nome do usuário atualmente logado (para verificação de senha).
    """
    print("INFO (Excluir): Iniciando fluxo de exclusão de registro.")

    # Passo 1: Pedir o CPF ao usuário
    cpf_alvo_str = simpledialog.askstring("Excluir Registro por CPF",
                                          "Digite o CPF (somente números ou com pontos/traço)\n"
                                          "do registro que deseja EXCLUIR PERMANENTEMENTE:",
                                          parent=None)

    # Passo 2: Verificar se o usuário forneceu um CPF ou cancelou
    if not cpf_alvo_str:
        print("INFO (Excluir): Usuário cancelou a entrada do CPF.")
        return

    print(f"INFO (Excluir): CPF fornecido para exclusão: '{cpf_alvo_str}'")

    # Passo 3: Validar o CPF (formato e dígitos verificadores)
    if not validar_cpf_completo(cpf_alvo_str):
        messagebox.showerror("CPF Inválido",
                             f"O CPF '{cpf_alvo_str}' parece ser inválido.\n"
                             "A exclusão foi cancelada.", parent=None)
        print(f"ERRO (Excluir): CPF '{cpf_alvo_str}' inválido. Exclusão cancelada.")
        return

    cpf_alvo_numeros = "".join(filter(str.isdigit, cpf_alvo_str))
    print(f"INFO (Excluir): CPF '{cpf_alvo_numeros}' validado. Buscando arquivos...")

    # Passo 4: Localizar o arquivo TXT correspondente
    arquivo_txt_encontrado, tipo_registro_encontrado = find_record_file_by_cpf(cpf_alvo_numeros)

    # Passo 5: Verificar se o arquivo TXT foi encontrado
    if not arquivo_txt_encontrado:
        messagebox.showinfo("Registro Não Encontrado",
                            f"Nenhum registro foi encontrado para o CPF: {cpf_alvo_numeros}.\n"
                            "Nenhum arquivo foi excluído.", parent=None)
        print(f"INFO (Excluir): Nenhum arquivo TXT encontrado para CPF {cpf_alvo_numeros}. Exclusão cancelada.")
        return

    # Se encontrou o TXT, tenta carregar dados para mostrar na confirmação
    print(f"INFO (Excluir): Arquivo TXT encontrado: {arquivo_txt_encontrado}. Carregando dados para confirmação...")
    dados_para_confirmacao = load_record_data(arquivo_txt_encontrado)
    nome_para_confirmacao = "Nome não disponível"
    tipo_para_confirmacao = tipo_registro_encontrado if tipo_registro_encontrado else "Tipo desconhecido"

    if dados_para_confirmacao and isinstance(dados_para_confirmacao, dict):
        nome_para_confirmacao = dados_para_confirmacao.get("Nome", "Nome não encontrado no arquivo")
        # Poderia pegar o tipo de dentro do arquivo se quisesse ser mais preciso
        # tipo_para_confirmacao = dados_para_confirmacao.get("TipoRegistro", tipo_para_confirmacao)
    elif dados_para_confirmacao is None:
         # Erro ao carregar, a função load já mostrou msg, mas avisamos aqui também
         print(f"AVISO (Excluir): Houve erro ao carregar dados de {arquivo_txt_encontrado} para confirmação.")
         nome_para_confirmacao = "[Erro ao carregar dados]"


    # Passo 6: Pedir confirmação explícita ao usuário
    print("INFO (Excluir): Solicitando confirmação do usuário...")
    confirmacao_usuario = messagebox.askyesno(
        "Confirmar Exclusão PERMANENTE",
        f"Você tem CERTEZA ABSOLUTA que deseja EXCLUIR este registro?\n\n"
        f"Tipo: {tipo_para_confirmacao}\n"
        f"Nome: {nome_para_confirmacao}\n"
        f"CPF: {cpf_alvo_numeros}\n\n"
        f"Serão excluídos os arquivos:\n"
        f" -> ...\\{os.path.basename(os.path.dirname(arquivo_txt_encontrado))}\\{os.path.basename(arquivo_txt_encontrado)}\n"
        f" -> ...\\{SUBFOLDER_CSV}\\{os.path.splitext(os.path.basename(arquivo_txt_encontrado))[0]}.csv\n\n" # Mostra o nome esperado do CSV
        "ESTA AÇÃO NÃO PODE SER DESFEITA!",
        icon='warning', # Ícone de aviso
        parent=None
    )

    # Passo 7: Verificar a confirmação do usuário
    if not confirmacao_usuario:
        print("INFO (Excluir): Usuário cancelou a exclusão na primeira confirmação.")
        messagebox.showinfo("Cancelado", "A exclusão do registro foi cancelada.", parent=None)
        return

    # Passo 8: Se confirmou, pedir a senha do usuário logado como segurança adicional
    print(f"INFO (Excluir): Usuário confirmou. Solicitando senha de '{usuario_logado}'...")
    senha_digitada_confirmacao = simpledialog.askstring(
        "Verificação de Segurança",
        f"Para confirmar a exclusão, por favor, digite a senha\n"
        f"do usuário logado ({usuario_logado}):",
        show='*', # Mostra '*' em vez da senha
        parent=None
    )

    # Passo 9: Verificar se a senha foi digitada
    if not senha_digitada_confirmacao:
        messagebox.showwarning("Cancelado", "Senha não fornecida. A exclusão foi cancelada.", parent=None)
        print("INFO (Excluir): Exclusão cancelada (senha de confirmação não fornecida).")
        return

    # Passo 10: Verificar a senha digitada contra a senha armazenada do usuário logado
    print(f"INFO (Excluir): Verificando senha fornecida para '{usuario_logado}'...")
    stored_salt = None
    stored_hash = None
    senha_verificada = False

    try:
        # Garante que o arquivo de usuários existe
        if not os.path.isfile(USUARIOS_FILE_PATH):
             messagebox.showerror("Erro Crítico", f"Arquivo de usuários não encontrado em:\n{USUARIOS_FILE_PATH}\nNão é possível verificar a senha para exclusão.", parent=None)
             print(f"ERRO (Excluir): Arquivo de usuários não encontrado. Abortando.")
             return

        # Lê o arquivo de usuários para encontrar o salt e hash do usuário logado
        with open(USUARIOS_FILE_PATH, 'r', encoding='utf-8') as f_users:
            for line in f_users:
                line = line.strip()
                if not line: continue
                try:
                    # user;salt;hash;role
                    user_file, salt_file, hash_file, role_file = line.split(';', 3)
                    # Compara o nome de usuário (ignorando maiúsculas/minúsculas)
                    if user_file.upper() == usuario_logado.upper():
                        stored_salt = salt_file
                        stored_hash = hash_file
                        print(f"DEBUG (Excluir): Salt/Hash encontrados para '{usuario_logado}'.")
                        break # Encontrou o usuário, pode parar de ler
                except ValueError:
                    print(f"AVISO (Excluir): Linha mal formada ignorada no arquivo de usuários: {line}")
                    continue # Ignora linhas mal formatadas

        # Verifica se encontrou os dados do usuário
        if not stored_salt or not stored_hash:
            messagebox.showerror("Erro Interno", f"Não foi possível encontrar os dados de segurança para o usuário '{usuario_logado}' no arquivo.\nA exclusão foi cancelada.", parent=None)
            print(f"ERRO (Excluir): Salt/Hash não encontrados para usuário '{usuario_logado}'.")
            return

        # Chama a função verify_password para comparar a senha digitada
        senha_verificada = verify_password(stored_salt, stored_hash, senha_digitada_confirmacao)

    except IOError as e_io_users:
         messagebox.showerror("Erro Leitura Usuários", f"Erro ao ler arquivo de usuários para verificar senha:\n{e_io_users}", parent=None)
         print(f"ERRO (Excluir): Erro de IO ao ler {USUARIOS_FILE_PATH}. Erro: {e_io_users}")
         return
    except Exception as e_verif_senha:
         messagebox.showerror("Erro Verificação", f"Erro inesperado durante a verificação da senha:\n{e_verif_senha}", parent=None)
         print(f"ERRO (Excluir): Erro inesperado ao verificar senha. Erro: {e_verif_senha}")
         return

    # Passo 11: Se a senha não for válida, cancelar
    if not senha_verificada:
        messagebox.showerror("Senha Incorreta", "A senha digitada está incorreta. A exclusão foi cancelada.", parent=None)
        print("INFO (Excluir): Exclusão cancelada (senha incorreta).")
        return

    # --- Se chegou até aqui, a senha está correta e o usuário confirmou ---
    print(f"INFO (Excluir): Senha verificada com sucesso para '{usuario_logado}'. Procedendo com a exclusão dos arquivos.")

    # Passo 12: Excluir os arquivos TXT e CSV
    sucesso_excluir_txt = False
    sucesso_excluir_csv = False

    # Tenta excluir o arquivo TXT
    try:
        if os.path.exists(arquivo_txt_encontrado):
            os.remove(arquivo_txt_encontrado)
            print(f"INFO (Excluir): Arquivo TXT excluído: {arquivo_txt_encontrado}")
            sucesso_excluir_txt = True
        else:
             print(f"AVISO (Excluir): Arquivo TXT não encontrado no momento da exclusão (já pode ter sido removido?): {arquivo_txt_encontrado}")
             sucesso_excluir_txt = True # Considera sucesso se já não existe
    except OSError as e_rm_txt:
        print(f"ERRO (Excluir): Falha ao excluir o arquivo TXT {arquivo_txt_encontrado}: {e_rm_txt}")
        messagebox.showerror("Erro ao Excluir TXT",
                             f"Não foi possível excluir o arquivo de texto:\n{arquivo_txt_encontrado}\n"
                             f"Erro: {e_rm_txt}\n\n"
                             "Verifique as permissões ou se o arquivo está em uso.", parent=None)
    except Exception as e_gen_rm_txt:
         print(f"ERRO (Excluir): Erro inesperado ao excluir TXT: {e_gen_rm_txt}")
         messagebox.showerror("Erro Inesperado", f"Erro inesperado ao excluir arquivo TXT:\n{e_gen_rm_txt}", parent=None)


    # Deriva o caminho esperado para o arquivo CSV
    arquivo_csv_esperado = _get_associated_csv_path(arquivo_txt_encontrado)

    # Tenta excluir o arquivo CSV
    if arquivo_csv_esperado:
        try:
            if os.path.exists(arquivo_csv_esperado):
                os.remove(arquivo_csv_esperado)
                print(f"INFO (Excluir): Arquivo CSV excluído: {arquivo_csv_esperado}")
                sucesso_excluir_csv = True
            else:
                print(f"AVISO (Excluir): Arquivo CSV não encontrado no momento da exclusão: {arquivo_csv_esperado}")
                sucesso_excluir_csv = True # Considera sucesso se já não existe
        except OSError as e_rm_csv:
            print(f"ERRO (Excluir): Falha ao excluir o arquivo CSV {arquivo_csv_esperado}: {e_rm_csv}")
            messagebox.showerror("Erro ao Excluir CSV",
                                 f"Não foi possível excluir o arquivo CSV correspondente:\n{arquivo_csv_esperado}\n"
                                 f"Erro: {e_rm_csv}\n\n"
                                 "Verifique as permissões ou se o arquivo está em uso.", parent=None)
            # Nota: O TXT pode ter sido excluído mesmo se o CSV falhar.
        except Exception as e_gen_rm_csv:
             print(f"ERRO (Excluir): Erro inesperado ao excluir CSV: {e_gen_rm_csv}")
             messagebox.showerror("Erro Inesperado", f"Erro inesperado ao excluir arquivo CSV:\n{e_gen_rm_csv}", parent=None)
    else:
        print("AVISO (Excluir): Não foi possível determinar o caminho do arquivo CSV correspondente. Pulando exclusão do CSV.")
        # Considerar se isso deve ser um erro ou não. Se o TXT foi excluído, talvez seja ok.

    # Passo 13: Mostrar mensagem final de sucesso (se ambos foram tratados)
    if sucesso_excluir_txt and sucesso_excluir_csv:
        messagebox.showinfo("Sucesso",
                            f"Registro de {tipo_para_confirmacao} ({nome_para_confirmacao})\n"
                            f"referente ao CPF {cpf_alvo_numeros} foi excluído com sucesso!",
                            parent=None)
        print(f"INFO (Excluir): Exclusão concluída para CPF {cpf_alvo_numeros}.")
    else:
         # Mensagens de erro específicas já foram mostradas
         print(f"AVISO (Excluir): Exclusão para CPF {cpf_alvo_numeros} concluída, mas com problemas (TXT: {sucesso_excluir_txt}, CSV: {sucesso_excluir_csv}).")


# --- Função para Gerar Relatório ---

def gerar_relatorio_simples():
    """
    Gera um relatório em arquivo de texto (.txt) listando informações básicas
    (Tipo, Nome, CPF, E-mail, Atividades) de todos os registros encontrados
    nas subpastas TXT. Pede ao usuário onde salvar o arquivo de relatório.
    """
    print("INFO (Relatório): Iniciando geração de relatório simples...")

    # Passo 1: Verificar se a pasta principal existe
    if not verificar_pasta_principal():
        messagebox.showerror("Erro Pasta Base", "A pasta base de registros não foi encontrada ou não pôde ser criada.\nNão é possível gerar o relatório.", parent=None)
        print("ERRO (Relatório): Pasta base não encontrada. Abortando.")
        return

    # Passo 2: Coletar dados de todos os registros
    lista_todos_os_dados = [] # Lista para guardar dicionários de dados de cada registro
    # Mapa das pastas de categoria para o tipo de registro padrão
    pastas_tipos_map = {
        SUBFOLDER_ALUNOS: "Aluno",
        SUBFOLDER_FUNCIONARIOS: "Funcionário",
        SUBFOLDER_PROFESSORES: "Professor"
    }

    print("INFO (Relatório): Varrendo pastas de categoria...")
    # Itera sobre cada pasta de categoria (Alunos, Funcionarios, Professores)
    for categoria_folder_name, record_type_default in pastas_tipos_map.items():
        # Monta o caminho para a subpasta TXT dentro da categoria
        txt_subfolder_path = os.path.join(APP_FOLDER_PATH, categoria_folder_name, SUBFOLDER_TXT)
        print(f"DEBUG (Relatório): Verificando pasta TXT: {txt_subfolder_path}")

        # Verifica se a pasta TXT existe
        if not os.path.isdir(txt_subfolder_path):
            print(f"DEBUG (Relatório): Pasta TXT '{txt_subfolder_path}' não existe. Pulando.")
            continue # Pula para a próxima categoria

        # Tenta listar os arquivos dentro da pasta TXT
        try:
            arquivos_na_pasta_txt = os.listdir(txt_subfolder_path)
            print(f"DEBUG (Relatório): {len(arquivos_na_pasta_txt)} itens encontrados em {txt_subfolder_path}.")

            # Itera sobre cada arquivo encontrado na pasta TXT
            for filename in arquivos_na_pasta_txt:
                # Verifica se o arquivo tem a extensão .txt (ignorando maiúsculas/minúsculas)
                if filename.lower().endswith(FILE_EXTENSION_TXT):
                    # Monta o caminho completo para o arquivo .txt
                    file_path_completo = os.path.join(txt_subfolder_path, filename)
                    # print(f"DEBUG (Relatório): Processando arquivo: {file_path_completo}")

                    # Carrega os dados do arquivo .txt usando a função load_record_data
                    record_data_dict = load_record_data(file_path_completo)

                    # Verifica se os dados foram carregados com sucesso (não None e não vazio)
                    if record_data_dict and isinstance(record_data_dict, dict):
                        # Adiciona um dicionário simplificado com os dados relevantes à lista
                        # Pega o tipo do campo 'TipoRegistro' se existir, senão usa o padrão da pasta
                        tipo_real_registro = record_data_dict.get("TipoRegistro", record_type_default)
                        dados_para_relatorio = {
                            "Tipo": tipo_real_registro,
                            "Nome": record_data_dict.get("Nome", "N/D"), # Usa N/D se o campo não existir
                            "CPF": record_data_dict.get("CPF", "N/D"),
                            "E-mail": record_data_dict.get("E-mail", "N/D"),
                            "Atividades": record_data_dict.get("Atividades", "N/D")
                        }
                        lista_todos_os_dados.append(dados_para_relatorio)
                        # print(f"DEBUG (Relatório): Dados adicionados para {filename}")
                    # else:
                        # load_record_data já imprimiu erro ou aviso se falhou ou retornou vazio

        except OSError as e_dir:
            print(f"AVISO (Relatório): Erro ao ler diretório {txt_subfolder_path}: {e_dir}")
            messagebox.showwarning("Aviso Leitura Diretório",
                                   f"Não foi possível ler todos os arquivos da pasta {txt_subfolder_path} para o relatório.\nErro: {e_dir}",
                                   parent=None)
            # Continua para a próxima pasta mesmo se uma falhar
        except Exception as e_proc:
             print(f"ERRO (Relatório): Erro inesperado ao processar pasta {txt_subfolder_path}: {e_proc}")
             messagebox.showerror("Erro Processamento Pasta",
                                  f"Ocorreu um erro inesperado ao processar a pasta {categoria_folder_name} para o relatório.\nErro: {e_proc}",
                                  parent=None)
             # Continua para a próxima pasta

    # Passo 3: Verificar se algum dado foi coletado
    if not lista_todos_os_dados:
        messagebox.showinfo("Relatório Vazio", "Nenhum registro válido foi encontrado nas pastas TXT para incluir no relatório.", parent=None)
        print("INFO (Relatório): Nenhum dado encontrado. Geração de relatório cancelada.")
        return

    # Passo 4: Pedir ao usuário onde salvar o arquivo de relatório
    print(f"INFO (Relatório): {len(lista_todos_os_dados)} registros coletados. Solicitando local para salvar...")
    try:
        # Sugere um nome de arquivo padrão com data/hora
        agora = datetime.datetime.now()
        timestamp_str = agora.strftime("%Y%m%d_%H%M%S")
        default_filename = f"Relatorio_Cadastros_{timestamp_str}.txt"

        # Abre a janela de diálogo "Salvar como"
        save_path = filedialog.asksaveasfilename(
            parent=None, # Janela pai
            title="Salvar Relatório de Cadastros Como...", # Título da janela
            initialfile=default_filename, # Nome de arquivo sugerido
            defaultextension=".txt", # Extensão padrão
            filetypes=[("Arquivos de Texto", "*.txt"), ("Todos os Arquivos", "*.*")] # Tipos de arquivo
        )

        # Verifica se o usuário selecionou um local ou cancelou
        if not save_path:
            print("INFO (Relatório): Geração de relatório cancelada pelo usuário (não selecionou local para salvar).")
            messagebox.showinfo("Cancelado", "Geração de relatório cancelada.", parent=None)
            return

        # Passo 5: Escrever os dados coletados no arquivo de relatório escolhido
        print(f"INFO (Relatório): Salvando relatório em: {save_path}")
        with open(save_path, 'w', encoding='utf-8') as f_report:
            # Escreve um cabeçalho para o relatório
            f_report.write("=" * 80 + "\n")
            f_report.write(f"RELATÓRIO GERAL DE CADASTROS\n")
            f_report.write(f"Gerado em: {agora.strftime('%d/%m/%Y %H:%M:%S')}\n")
            f_report.write("=" * 80 + "\n\n")

            # Escreve o cabeçalho das colunas (ajuste as larguras conforme necessário)
            # Formato: {Campo:<Largura} - Alinha à esquerda
            cabecalho = f"{'Tipo':<12} | {'Nome':<35} | {'CPF':<15} | {'E-mail':<35} | {'Atividades'}\n"
            f_report.write(cabecalho)
            # Escreve uma linha separadora
            largura_total_aprox = 12 + 3 + 35 + 3 + 15 + 3 + 35 + 3 + 20 # Estimativa
            f_report.write("-" * largura_total_aprox + "\n")

            # Ordena os dados (opcional, aqui por Nome) antes de escrever
            # Define uma função simples para obter a chave de ordenação (Nome)
            def obter_chave_nome(item_dicionario):
                return item_dicionario.get("Nome", "").lower() # Ordena por nome, case-insensitive

            dados_ordenados = sorted(lista_todos_os_dados, key=obter_chave_nome)


            # Itera sobre os dados ordenados e escreve cada registro como uma linha
            for dados_registro in dados_ordenados:
                # Formata a linha limitando o tamanho de cada campo para evitar quebra de linha feia
                linha_formatada = (
                    f"{dados_registro['Tipo']:<12.12} | "
                    f"{dados_registro['Nome']:<35.35} | "
                    f"{dados_registro['CPF']:<15.15} | "
                    f"{dados_registro['E-mail']:<35.35} | "
                    f"{dados_registro['Atividades']}" # Atividades pode estourar a linha
                )
                f_report.write(linha_formatada + "\n")

            # Escreve um rodapé com o total de registros
            f_report.write("\n" + "=" * 80 + "\n")
            f_report.write(f"Total de Registros Encontrados: {len(lista_todos_os_dados)}\n")
            f_report.write("=" * 80 + "\n")

        # Se chegou aqui, o arquivo foi escrito
        print(f"INFO (Relatório): Relatório salvo com sucesso em: {save_path}")
        messagebox.showinfo("Relatório Gerado",
                            f"Relatório gerado com {len(lista_todos_os_dados)} registros.\n"
                            f"Salvo com sucesso em:\n{save_path}", parent=None)

    except IOError as e_io_report:
        # Erro ao tentar salvar o arquivo de relatório
        print(f"ERRO (Relatório): Falha ao salvar o arquivo de relatório em {save_path}: {e_io_report}")
        messagebox.showerror("Erro ao Salvar Relatório", f"Não foi possível salvar o arquivo de relatório:\n{e_io_report}", parent=None)
    except Exception as e_gen_save_report:
        # Outro erro inesperado durante a geração/salvamento do relatório
        print(f"ERRO (Relatório): Erro Inesperado ao gerar/salvar relatório: {e_gen_save_report}")
        messagebox.showerror("Erro Inesperado no Relatório", f"Ocorreu um erro inesperado ao gerar/salvar o relatório:\n{e_gen_save_report}", parent=None)


# --- Janelas da Interface Gráfica (Login, Gerenciamento, Consulta, Cadastro) ---

def janela_login():
    """Cria e exibe a janela de login inicial."""
    print("DEBUG (Login): Criando janela de login.")
    login_window = tk.Tk()
    login_window.title("Login do Sistema de Registros")
    login_window.geometry("350x200")
    login_window.resizable(False, False) # Impede redimensionar

    # Variáveis Tkinter para os campos de usuário e senha
    usuario_var = tk.StringVar()
    senha_var = tk.StringVar()

    # --- Função interna para tentar o login ---
    def _tentar_realizar_login():
        """
        Função chamada pelo botão Login.
        Valida as credenciais contra o arquivo usuarios.txt (com hash+salt).
        """
        nome_usuario_digitado = usuario_var.get().strip()
        senha_digitada = senha_var.get() # Senha não deve ter strip()

        print(f"DEBUG (Login): Tentativa de login para usuário: '{nome_usuario_digitado}'")

        # Validação básica: campos não podem estar vazios
        if not nome_usuario_digitado or not senha_digitada:
            messagebox.showerror("Campos Vazios", "Usuário e Senha são obrigatórios!", parent=login_window)
            return

        # Flags para controlar o processo de verificação
        usuario_foi_encontrado_no_arquivo = False
        login_bem_sucedido = False
        role_do_usuario_logado = None

        # Tenta abrir e ler o arquivo de usuários
        try:
            # Verifica se o arquivo existe antes de tentar abrir
            if not os.path.isfile(USUARIOS_FILE_PATH):
                messagebox.showerror("Erro Crítico de Arquivo",
                                     f"Arquivo de usuários não encontrado em:\n{USUARIOS_FILE_PATH}\n"
                                     "Não é possível fazer login. Verifique a configuração.",
                                     parent=login_window)
                print(f"ERRO (Login): Arquivo de usuários não existe em {USUARIOS_FILE_PATH}.")
                return # Sai da função de login

            # Abre o arquivo para leitura
            with open(USUARIOS_FILE_PATH, 'r', encoding='utf-8') as f_users:
                # Lê cada linha do arquivo
                for numero_linha, linha in enumerate(f_users):
                    linha = linha.strip()
                    # Ignora linhas em branco
                    if not linha:
                        continue

                    # Tenta processar a linha no formato user;salt;hash;role
                    try:
                        stored_user, stored_salt, stored_hash, stored_role = linha.split(';', 3)

                        # Compara o nome de usuário (ignorando maiúsculas/minúsculas)
                        if stored_user.upper() == nome_usuario_digitado.upper():
                            usuario_foi_encontrado_no_arquivo = True
                            print(f"DEBUG (Login): Usuário '{stored_user}' encontrado na linha {numero_linha+1}. Verificando senha...")

                            # Verifica a senha usando a função verify_password
                            senha_correta = verify_password(stored_salt, stored_hash, senha_digitada)

                            if senha_correta:
                                # Login bem-sucedido!
                                login_bem_sucedido = True
                                role_do_usuario_logado = stored_role
                                print(f"INFO: Login bem-sucedido para usuário: {stored_user} (Role: {role_do_usuario_logado})")

                                # Fecha a janela de login
                                login_window.destroy()
                                print("DEBUG (Login): Janela de login fechada.")

                                # Abre o menu principal, passando o nome de usuário e o role
                                menu_principal(stored_user, role_do_usuario_logado)
                                return # Sai da função _tentar_realizar_login e do loop

                            else:
                                # Usuário encontrado, mas senha incorreta
                                print(f"AVISO (Login): Senha incorreta para usuário '{stored_user}'.")
                                messagebox.showerror("Login Falhou", "Senha incorreta.", parent=login_window)
                                senha_var.set("") # Limpa o campo de senha
                                pass_entry.focus_set() # Coloca o foco de volta na senha
                                return # Sai da função, mas não do loop (poderia haver outro usuário com nome similar?) - Melhor sair.

                    except ValueError:
                        # Erro se a linha não tiver o formato esperado
                        print(f"AVISO (Login): Linha {numero_linha+1} mal formada ignorada em {USUARIOS_FILE_NAME}: '{linha}'")
                        # Opcional: Mostrar aviso ao usuário
                        # messagebox.showwarning("Aviso Formato", f"Linha mal formada ignorada no arquivo de usuários:\n{linha}", parent=login_window)
                    except Exception as e_line:
                        # Outro erro ao processar a linha
                        print(f"ERRO (Login): Erro ao processar linha {numero_linha+1} de usuário: '{linha}'. Erro: {e_line}")
                        messagebox.showerror("Erro Processamento Usuário", f"Erro ao processar linha de usuário:\n{linha}\n{e_line}", parent=login_window)
                        # Considerar se deve parar ou continuar

            # Fim do loop de leitura do arquivo

            # Verifica se o usuário foi encontrado após ler todo o arquivo
            if not usuario_foi_encontrado_no_arquivo:
                print(f"AVISO (Login): Usuário '{nome_usuario_digitado}' não encontrado no arquivo.")
                messagebox.showerror("Login Falhou", "Usuário não encontrado.", parent=login_window)
                usuario_var.set("") # Limpa campo usuário
                senha_var.set("")   # Limpa campo senha
                user_entry.focus_set() # Foco no usuário

        except FileNotFoundError: # Segurança extra, já verificado acima
            print(f"ERRO CRÍTICO (Login): FileNotFoundError - {USUARIOS_FILE_PATH} (isso não deveria acontecer).")
            messagebox.showerror("Erro Crítico de Arquivo", f"Arquivo de usuários não encontrado!\n{USUARIOS_FILE_PATH}", parent=login_window)
        except IOError as e_io:
            print(f"ERRO (Login): Erro de IO ao ler {USUARIOS_FILE_PATH}: {e_io}")
            messagebox.showerror("Erro de Leitura", f"Não foi possível ler o arquivo de usuários:\n{e_io}", parent=login_window)
        except Exception as e_geral:
            print(f"ERRO (Login): Erro inesperado durante o login: {e_geral}")
            messagebox.showerror("Erro Inesperado", f"Ocorreu um erro inesperado durante o login:\n{e_geral}", parent=login_window)

    # --- Layout da Janela de Login ---
    login_frame = ttk.Frame(login_window, padding="20")
    login_frame.pack(expand=True, fill=tk.BOTH)

    # Label e Entrada para Usuário
    ttk.Label(login_frame, text="Usuário:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
    user_entry = ttk.Entry(login_frame, textvariable=usuario_var, width=30)
    user_entry.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=5)
    user_entry.focus_set() # Foco inicial aqui

    # Label e Entrada para Senha
    ttk.Label(login_frame, text="Senha:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
    pass_entry = ttk.Entry(login_frame, textvariable=senha_var, show="*", width=30) # show="*" esconde a senha
    pass_entry.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=5)

    # Frame para os botões
    botoes_login_frame = ttk.Frame(login_frame)
    botoes_login_frame.grid(row=2, column=0, columnspan=2, pady=15)

    # Botão Login
    login_button = ttk.Button(botoes_login_frame, text="Login", command=_tentar_realizar_login, width=10)
    login_button.pack(side=tk.LEFT, padx=10)

    # Botão Sair
    cancel_button = ttk.Button(botoes_login_frame, text="Sair", command=login_window.destroy, width=10)
    cancel_button.pack(side=tk.LEFT, padx=10)

    # --- Binds de Teclado (Enter) ---
    # Enter no campo usuário -> foca no campo senha
    def _focar_senha(event=None):
        pass_entry.focus_set()
    user_entry.bind("<Return>", _focar_senha)

    # Enter no campo senha -> tenta login
    def _trigger_login(event=None):
        _tentar_realizar_login()
    pass_entry.bind("<Return>", _trigger_login)


    # Configura a coluna das entradas para expandir
    login_frame.grid_columnconfigure(1, weight=1)

    # Inicia o loop principal da janela de login
    login_window.mainloop()
    print("DEBUG (Login): Janela de login fechada (mainloop terminou).")


def janela_gerenciar_usuarios():
    """
    Cria e exibe a janela para adicionar novos usuários (tipo 'employee').
    Apenas o administrador (role 'admin') pode acessar esta janela.
    """
    print("DEBUG (Gerenciar Usuários): Abrindo janela...")
    manager_window = tk.Toplevel()
    manager_window.title("Gerenciar Usuários (Adicionar Funcionário)")
    manager_window.geometry("450x280") # Tamanho da janela

    # Variáveis Tkinter para os campos
    novo_usuario_var = tk.StringVar()
    nova_senha_var = tk.StringVar()
    confirmar_senha_var = tk.StringVar()

    # --- Função interna para adicionar usuário ---
    def _adicionar_novo_funcionario():
        """
        Função chamada pelo botão 'Adicionar Funcionário'.
        Valida os dados e adiciona o novo usuário ao arquivo usuarios.txt.
        """
        # Coleta os dados dos campos
        novo_username = novo_usuario_var.get().strip()
        nova_password = nova_senha_var.get() # Sem strip
        confirm_password = confirmar_senha_var.get() # Sem strip

        print(f"DEBUG (Gerenciar Usuários): Tentando adicionar usuário '{novo_username}'...")

        # Passo 1: Validações básicas de entrada
        if not novo_username or not nova_password or not confirm_password:
            messagebox.showerror("Erro", "Todos os campos (Usuário, Nova Senha, Confirmar Senha) são obrigatórios!", parent=manager_window)
            return

        if nova_password != confirm_password:
            messagebox.showerror("Erro", "As senhas digitadas não coincidem!", parent=manager_window)
            # Limpa apenas os campos de senha
            nova_senha_var.set("")
            confirmar_senha_var.set("")
            new_pass_entry.focus_set() # Foco no campo de nova senha
            return

        # Validação de complexidade/tamanho da senha (exemplo: mínimo 6 caracteres)
        if len(nova_password) < 6:
             messagebox.showerror("Erro", "A senha deve ter pelo menos 6 caracteres.", parent=manager_window)
             nova_senha_var.set("")
             confirmar_senha_var.set("")
             new_pass_entry.focus_set()
             return

        # Impede recriar o usuário ADM padrão
        if novo_username.upper() == DEFAULT_ADMIN_USER:
            messagebox.showerror("Erro", f"Não é permitido criar um usuário com o nome reservado '{DEFAULT_ADMIN_USER}'.", parent=manager_window)
            novo_usuario_var.set("") # Limpa o campo usuário
            new_user_entry.focus_set()
            return

        # Passo 2: Verificar se o nome de usuário já existe
        usuario_ja_existe = False
        try:
            # Verifica se o arquivo existe antes de ler
            if os.path.isfile(USUARIOS_FILE_PATH):
                with open(USUARIOS_FILE_PATH, 'r', encoding='utf-8') as f_check:
                    for line in f_check:
                        line = line.strip()
                        if line:
                            # Pega apenas a primeira parte (nome de usuário) antes do primeiro ';'
                            parts = line.split(';', 1)
                            if len(parts) > 0 and parts[0].upper() == novo_username.upper():
                                usuario_ja_existe = True
                                print(f"DEBUG (Gerenciar Usuários): Verificação - Usuário '{novo_username}' já existe.")
                                break # Para de verificar assim que encontrar
            # else: Se o arquivo não existe, o usuário obviamente não existe nele.

        except Exception as e_check:
            # Erro durante a verificação
            messagebox.showerror("Erro de Leitura", f"Erro ao verificar se o usuário já existe:\n{e_check}", parent=manager_window)
            print(f"ERRO (Gerenciar Usuários): Falha ao verificar existência do usuário. Erro: {e_check}")
            return # Aborta a adição

        # Se o usuário já existe, mostra erro e para
        if usuario_ja_existe:
            messagebox.showerror("Usuário Existente", f"O nome de usuário '{novo_username}' já está em uso.\nPor favor, escolha outro nome.", parent=manager_window)
            novo_usuario_var.set("") # Limpa o campo usuário
            new_user_entry.focus_set() # Foca nele novamente
            return

        # --- Se passou por todas as validações ---
        print(f"DEBUG (Gerenciar Usuários): Validações OK para '{novo_username}'. Tentando adicionar...")

        # Passo 3: Adicionar o novo usuário ao arquivo
        try:
            # Gera o hash e salt para a nova senha
            novo_salt_hex, novo_hashed_hex = hash_password(nova_password)

            # Verifica se o hashing funcionou
            if novo_salt_hex and novo_hashed_hex:
                # Define o role como 'employee' para novos usuários
                novo_role = EMPLOYEE_ROLE
                # Cria a linha a ser adicionada no formato user;salt;hash;role
                nova_linha_usuario = f"{novo_username};{novo_salt_hex};{novo_hashed_hex};{novo_role}\n"

                # Abre o arquivo em modo 'append' para adicionar a linha no final
                with open(USUARIOS_FILE_PATH, 'a', encoding='utf-8') as f_add:
                    f_add.write(nova_linha_usuario)

                # Informa o sucesso e limpa os campos
                messagebox.showinfo("Sucesso", f"Funcionário '{novo_username}' adicionado com sucesso!", parent=manager_window)
                print(f"INFO (Gerenciar Usuários): Usuário '{novo_username}' (role: {novo_role}) adicionado.")
                # Limpa todos os campos do formulário
                novo_usuario_var.set("")
                nova_senha_var.set("")
                confirmar_senha_var.set("")
                new_user_entry.focus_set() # Coloca o foco de volta no campo usuário

            else:
                # Se hash_password falhou
                print(f"ERRO CRÍTICO (Gerenciar Usuários): Falha ao gerar hash/salt para o novo usuário '{novo_username}'.")
                messagebox.showerror("Erro Crítico de Hashing",
                                     f"Não foi possível gerar a senha segura para o novo usuário '{novo_username}'.\n"
                                     "O usuário NÃO foi adicionado.",
                                     parent=manager_window)

        except IOError as e_write:
            messagebox.showerror("Erro de Escrita", f"Erro ao salvar o novo usuário no arquivo:\n{e_write}", parent=manager_window)
            print(f"ERRO (Gerenciar Usuários): Falha ao escrever no arquivo {USUARIOS_FILE_PATH}. Erro: {e_write}")
        except Exception as e_add_inesperado:
            messagebox.showerror("Erro Inesperado", f"Ocorreu um erro inesperado ao adicionar o usuário:\n{e_add_inesperado}", parent=manager_window)
            print(f"ERRO (Gerenciar Usuários): Erro inesperado ao adicionar usuário. Erro: {e_add_inesperado}")

    # --- Layout da Janela de Gerenciamento ---
    gerenciar_frame = ttk.Frame(manager_window, padding="20")
    gerenciar_frame.pack(expand=True, fill=tk.BOTH)

    # Novo Usuário
    ttk.Label(gerenciar_frame, text="Novo Usuário (Funcionário):").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
    new_user_entry = ttk.Entry(gerenciar_frame, textvariable=novo_usuario_var, width=30)
    new_user_entry.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=5)
    new_user_entry.focus_set() # Foco inicial

    # Nova Senha
    ttk.Label(gerenciar_frame, text="Nova Senha:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
    new_pass_entry = ttk.Entry(gerenciar_frame, textvariable=nova_senha_var, show="*", width=30)
    new_pass_entry.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=5)

    # Confirmar Senha
    ttk.Label(gerenciar_frame, text="Confirmar Senha:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
    confirm_pass_entry = ttk.Entry(gerenciar_frame, textvariable=confirmar_senha_var, show="*", width=30)
    confirm_pass_entry.grid(row=2, column=1, sticky=tk.EW, pady=5, padx=5)

    # Bind de Enter no campo Confirmar Senha para tentar adicionar
    def _trigger_adicionar(event=None):
        _adicionar_novo_funcionario()
    confirm_pass_entry.bind("<Return>", _trigger_adicionar)

    # Botão Adicionar
    button_add = ttk.Button(gerenciar_frame, text="Adicionar Funcionário", command=_adicionar_novo_funcionario)
    button_add.grid(row=3, column=0, columnspan=2, pady=(15, 5)) # pady com tupla (top, bottom)

    # Botão Fechar
    button_close = ttk.Button(gerenciar_frame, text="Fechar Janela", command=manager_window.destroy)
    button_close.grid(row=4, column=0, columnspan=2, pady=5)

    # Configura expansão da coluna de entrada
    gerenciar_frame.grid_columnconfigure(1, weight=1)

    print("DEBUG (Gerenciar Usuários): Janela criada e pronta.")


def janela_consulta(campo_busca):
    """
    Cria e exibe a janela para consultar registros por Nome, CPF ou Atividade.
    Os resultados são exibidos em um ttk.Treeview.
    Busca os dados nos arquivos .txt dentro das subpastas TXT.

    Args:
        campo_busca (str): O campo pelo qual buscar ("nome", "cpf" ou "atividade").
    """
    print(f"DEBUG (Consulta): Abrindo janela de consulta por '{campo_busca}'.")
    janela_consulta_gui = tk.Toplevel()
    janela_consulta_gui.title(f"Consulta de Registros por {campo_busca.capitalize()}")
    janela_consulta_gui.minsize(750, 450) # Tamanho mínimo da janela

    # Variável para o campo de entrada da pesquisa
    termo_pesquisa_var = tk.StringVar()
    # Variável para exibir o status da busca
    status_busca_var = tk.StringVar()

    # --- Frame Superior: Entrada de Pesquisa e Botão ---
    frame_pesquisa = ttk.Frame(janela_consulta_gui, padding=(10, 10, 10, 5))
    frame_pesquisa.pack(fill=tk.X) # Preenche horizontalmente

    ttk.Label(frame_pesquisa, text=f"Pesquisar por {campo_busca.capitalize()}:").pack(side=tk.LEFT, padx=(0, 5))
    pesquisa_entry = ttk.Entry(frame_pesquisa, textvariable=termo_pesquisa_var, width=40)
    pesquisa_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5) # Expande para preencher espaço
    pesquisa_entry.focus_set() # Foco inicial

    # --- Função interna que realiza a consulta ---
    def _realizar_consulta_wrapper():
        """Pega o termo, chama a função de busca e atualiza a Treeview."""
        termo_digitado = termo_pesquisa_var.get().strip().lower() # Pega, limpa, minúsculas
        print(f"DEBUG (Consulta): Botão Buscar clicado. Termo='{termo_digitado}'")

        # Limpa resultados anteriores da Treeview
        print("DEBUG (Consulta): Limpando resultados anteriores da Treeview...")
        # Itera sobre todos os itens filhos diretos da raiz da Treeview
        for item_id in tree_resultados.get_children():
            tree_resultados.delete(item_id) # Remove o item

        # Atualiza o status para indicar que a busca começou
        status_busca_var.set("Buscando registros...")
        janela_consulta_gui.update_idletasks() # Força a atualização da interface gráfica

        # Validação: não busca se o termo estiver vazio
        if not termo_digitado:
            messagebox.showwarning("Atenção", "Por favor, digite um valor para a pesquisa.", parent=janela_consulta_gui)
            status_busca_var.set("Digite um termo para buscar.")
            return

        # Verifica se a pasta base existe (essencial para buscar)
        if not verificar_pasta_principal():
            status_busca_var.set("Erro: Pasta base de registros não encontrada.")
            # A função verificar_pasta_principal já mostra erro
            return

        # Inicia a busca nos arquivos
        resultados_encontrados_count = 0
        pastas_tipos_map = {
            SUBFOLDER_ALUNOS: "Aluno",
            SUBFOLDER_FUNCIONARIOS: "Funcionário",
            SUBFOLDER_PROFESSORES: "Professor"
        }

        # Itera sobre as categorias
        for categoria_folder_name, record_type_default in pastas_tipos_map.items():
            # Define o caminho para a pasta TXT desta categoria
            txt_subfolder_path = os.path.join(APP_FOLDER_PATH, categoria_folder_name, SUBFOLDER_TXT)

            # Verifica se a pasta TXT existe
            if not os.path.isdir(txt_subfolder_path):
                continue # Pula para a próxima categoria

            # Tenta listar arquivos na pasta TXT
            try:
                for filename in os.listdir(txt_subfolder_path):
                    # Considera apenas arquivos .txt
                    if filename.lower().endswith(FILE_EXTENSION_TXT):
                        file_path_completo = os.path.join(txt_subfolder_path, filename)
                        # Carrega os dados do arquivo TXT
                        record_data = load_record_data(file_path_completo)

                        # Se carregou dados com sucesso (não None e não vazio)
                        if record_data and isinstance(record_data, dict):
                            encontrou_match = False # Flag para esta registro

                            # Lógica de correspondência (case-insensitive)
                            # Compara com o campo apropriado baseado em 'campo_busca'
                            if campo_busca == "nome":
                                nome_no_registro = record_data.get("Nome", "").lower()
                                if termo_digitado in nome_no_registro:
                                    encontrou_match = True
                            elif campo_busca == "cpf":
                                cpf_no_registro_limpo = ''.join(filter(str.isdigit, record_data.get("CPF", "")))
                                termo_digitado_limpo = ''.join(filter(str.isdigit, termo_digitado))
                                # Permite busca parcial ou exata se o termo limpo não for vazio
                                if termo_digitado_limpo and termo_digitado_limpo in cpf_no_registro_limpo:
                                    encontrou_match = True
                            elif campo_busca == "atividade":
                                atividades_no_registro = record_data.get("Atividades", "").lower()
                                if termo_digitado in atividades_no_registro:
                                    encontrou_match = True

                            # Se encontrou uma correspondência neste registro...
                            if encontrou_match:
                                resultados_encontrados_count += 1 # Incrementa o contador
                                # Pega os dados para exibir na Treeview (com valor padrão se faltar)
                                tipo_reg = record_data.get("TipoRegistro", record_type_default)
                                nome_reg = record_data.get("Nome", "")
                                cpf_reg = record_data.get("CPF", "")
                                email_reg = record_data.get("E-mail", "")
                                atividades_reg = record_data.get("Atividades", "")
                                # Monta a tupla de valores na ordem das colunas da Treeview
                                valores_linha = (tipo_reg, nome_reg, cpf_reg, email_reg, atividades_reg)
                                # Insere a nova linha na Treeview
                                tree_resultados.insert('', tk.END, values=valores_linha)
                                # print(f"DEBUG (Consulta): Match encontrado em {filename}. Adicionado à Treeview.")

            except OSError as e_dir_consulta:
                print(f"AVISO (Consulta): Erro ao listar diretório {txt_subfolder_path}: {e_dir_consulta}")
                # Não interrompe, tenta as outras pastas
            except Exception as e_proc_consulta:
                print(f"ERRO (Consulta): Erro inesperado ao processar pasta {txt_subfolder_path}: {e_proc_consulta}")
                # Não interrompe

        # Fim dos loops de busca

        # Atualiza o status final baseado no número de resultados
        if resultados_encontrados_count == 0:
            status_busca_var.set(f"Nenhum resultado encontrado para '{termo_pesquisa_var.get()}'.")
            print(f"INFO (Consulta): Busca concluída. Nenhum resultado.")
        else:
            plural = "s" if resultados_encontrados_count > 1 else ""
            status_busca_var.set(f"{resultados_encontrados_count} resultado{plural} encontrado{plural}.")
            print(f"INFO (Consulta): Busca concluída. {resultados_encontrados_count} resultado(s) encontrado(s).")

    # Botão para iniciar a busca
    botao_pesquisar = ttk.Button(frame_pesquisa, text="Buscar", command=_realizar_consulta_wrapper)
    botao_pesquisar.pack(side=tk.LEFT, padx=(5, 0))

    # Bind de Enter na caixa de pesquisa para também iniciar a busca
    def _trigger_consulta(event=None):
        _realizar_consulta_wrapper()
    pesquisa_entry.bind("<Return>", _trigger_consulta)

    # --- Frame Central: Treeview com Resultados e Scrollbars ---
    frame_resultados = ttk.Frame(janela_consulta_gui, padding=(10, 0, 10, 5))
    frame_resultados.pack(fill=tk.BOTH, expand=True) # Preenche e expande

    # Define as colunas da Treeview (identificadores internos)
    colunas_treeview = ('tipo', 'nome', 'cpf', 'email', 'atividades')
    # Cria a Treeview
    tree_resultados = ttk.Treeview(frame_resultados, columns=colunas_treeview, show='headings') # show='headings' mostra só cabeçalhos

    # Configura os cabeçalhos (texto exibido) e as colunas (largura, alinhamento)
    tree_resultados.heading('tipo', text='Tipo', anchor=tk.W)
    tree_resultados.column('tipo', width=80, anchor=tk.W, stretch=tk.NO) # stretch=NO impede redimensionar coluna
    tree_resultados.heading('nome', text='Nome', anchor=tk.W)
    tree_resultados.column('nome', width=200, anchor=tk.W)
    tree_resultados.heading('cpf', text='CPF', anchor=tk.CENTER) # Centraliza cabeçalho e conteúdo
    tree_resultados.column('cpf', width=110, anchor=tk.CENTER, stretch=tk.NO)
    tree_resultados.heading('email', text='E-mail', anchor=tk.W)
    tree_resultados.column('email', width=180, anchor=tk.W)
    tree_resultados.heading('atividades', text='Atividades', anchor=tk.W)
    tree_resultados.column('atividades', width=250, anchor=tk.W) # Coluna larga para atividades

    # Scrollbars (vertical e horizontal)
    scrollbar_y = ttk.Scrollbar(frame_resultados, orient=tk.VERTICAL, command=tree_resultados.yview)
    tree_resultados.configure(yscrollcommand=scrollbar_y.set)
    scrollbar_x = ttk.Scrollbar(frame_resultados, orient=tk.HORIZONTAL, command=tree_resultados.xview)
    tree_resultados.configure(xscrollcommand=scrollbar_x.set)

    # Posiciona a Treeview e as Scrollbars usando grid dentro do frame_resultados
    frame_resultados.grid_rowconfigure(0, weight=1)    # Linha 0 (Treeview) expande verticalmente
    frame_resultados.grid_columnconfigure(0, weight=1) # Coluna 0 (Treeview) expande horizontalmente
    tree_resultados.grid(row=0, column=0, sticky='nsew') # Treeview ocupa o espaço
    scrollbar_y.grid(row=0, column=1, sticky='ns')      # Scroll Y na coluna 1, estica verticalmente
    scrollbar_x.grid(row=1, column=0, sticky='ew')      # Scroll X na linha 1, estica horizontalmente

    # --- Frame Inferior: Status Label e Botão Fechar ---
    frame_inferior = ttk.Frame(janela_consulta_gui, padding=(10, 5, 10, 10))
    frame_inferior.pack(side=tk.BOTTOM, fill=tk.X) # Fica na parte de baixo

    # Status Label (à esquerda)
    status_label = ttk.Label(frame_inferior, textvariable=status_busca_var, foreground="grey", anchor=tk.W)
    status_label.pack(side=tk.LEFT, fill=tk.X, expand=True) # Ocupa espaço à esquerda

    # Botão Fechar (à direita)
    botao_fechar = ttk.Button(frame_inferior, text="Fechar Consulta", command=janela_consulta_gui.destroy)
    botao_fechar.pack(side=tk.RIGHT) # Fica à direita

    print("DEBUG (Consulta): Janela de consulta criada e pronta.")


def janela_cadastro(tipo_registro_novo):
    """
    Cria e exibe a janela para cadastrar um novo registro
    (Aluno, Funcionário ou Professor).

    Args:
        tipo_registro_novo (str): O tipo de registro a ser cadastrado.
    """
    print(f"DEBUG (Cadastro): Abrindo janela de cadastro para tipo '{tipo_registro_novo}'.")
    janela_cadastro_gui = tk.Toplevel()
    janela_cadastro_gui.title(f"Novo Cadastro de {tipo_registro_novo}")
    # janela_cadastro_gui.geometry("500x550") # Ajustar tamanho se necessário

    # --- Função interna para validar formato do CPF enquanto digita ---
    def _validar_entrada_cpf(valor_futuro_entry):
        """Permite apenas dígitos e no máximo 11 caracteres no campo CPF."""
        # Se o campo estiver vazio, permite
        if valor_futuro_entry == "":
            return True
        # Se o valor contém apenas dígitos E tem 11 caracteres ou menos, permite
        if valor_futuro_entry.isdigit() and len(valor_futuro_entry) <= 11:
            return True
        # Caso contrário, rejeita a edição
        return False
    # Registra a função de validação para ser usada pelo Tkinter
    validador_cpf_registrado_cmd = (janela_cadastro_gui.register(_validar_entrada_cpf), '%P') # '%P' passa o valor que o Entry teria


    # --- Variáveis Tkinter para os campos do formulário ---
    nome_var = tk.StringVar()
    endereco_var = tk.StringVar()
    cidade_var = tk.StringVar()
    estado_var = tk.StringVar()
    cpf_var = tk.StringVar()
    email_var = tk.StringVar()
    sexo_var = tk.StringVar(value="Masculino") # Define 'Masculino' como valor padrão inicial
    # Dicionário para as BooleanVars das atividades (Checkbuttons)
    atividades_vars_dict = {}
    lista_atividades = ["Musculação", "CrossFit", "Natação", "Dança", "Funcional", "Pilates", "Yoga"]
    # Cria uma BooleanVar para cada atividade possível, inicializada como False
    for nome_ativ in lista_atividades:
        atividades_vars_dict[nome_ativ] = tk.BooleanVar(value=False)

    # --- Função interna para salvar o novo cadastro ---
    def _salvar_novo_registro():
        """
        Função chamada pelo botão 'Salvar Cadastro'.
        Coleta os dados, valida tudo (incluindo CPF completo e unicidade)
        e chama `salvar_dados_individual`.
        """
        print("DEBUG (Cadastro): Botão Salvar clicado. Coletando dados do formulário...")

        # Passo 1: Coletar os dados das variáveis Tkinter
        dados_coletados_cadastro = {
            "TipoRegistro": tipo_registro_novo, # Pega o tipo passado para a janela
            "Nome": nome_var.get().strip(),
            "Endereço": endereco_var.get().strip(),
            "Cidade": cidade_var.get().strip(),
            "Estado": estado_var.get(), # Combobox já garante valor da lista ou vazio
            "CPF": cpf_var.get().strip(), # CPF já deve ter sido validado no formato
            "E-mail": email_var.get().strip(),
            "Sexo": sexo_var.get(), # Radiobutton garante um dos valores
            # Junta as atividades marcadas em uma string
            "Atividades": ", ".join([nome_ativ for nome_ativ, var_bool in atividades_vars_dict.items() if var_bool.get()]),
            # Pega o texto da caixa de Observação
            "Observação": observacao_entry.get("1.0", tk.END).strip()
        }
        # print(f"DEBUG (Cadastro): Dados coletados: {dados_coletados_cadastro}") # Cuidado ao logar dados sensíveis

        # Passo 2: Validação dos dados coletados
        print("DEBUG (Cadastro): Validando dados coletados...")
        # Campos obrigatórios (todos exceto Atividades e Observação)
        campos_obrigatorios = ["Nome", "Endereço", "Cidade", "Estado", "CPF", "E-mail", "Sexo"]
        # Encontra quais campos obrigatórios estão vazios
        campos_faltando_lista = []
        for campo_obr in campos_obrigatorios:
            if not dados_coletados_cadastro.get(campo_obr):
                campos_faltando_lista.append(campo_obr)

        # Se algum obrigatório faltar, mostra erro
        if campos_faltando_lista:
            campos_faltando_str = ", ".join(campos_faltando_lista)
            messagebox.showerror("Campos Obrigatórios",
                                 f"Por favor, preencha os seguintes campos obrigatórios:\n{campos_faltando_str}",
                                 parent=janela_cadastro_gui)
            print(f"ERRO (Cadastro): Validação falhou - Campos obrigatórios faltando: {campos_faltando_str}")
            # Idealmente, focar no primeiro campo faltando
            if campos_faltando_lista:
                 # Mapeia nome do campo para widget (requer guardar os widgets) - Simplificação: focar no nome
                 nome_entry.focus_set()
            return # Para o processo

        # Validação Completa do CPF (dígitos verificadores)
        cpf_para_validar = dados_coletados_cadastro["CPF"]
        if not validar_cpf_completo(cpf_para_validar):
            messagebox.showerror("CPF Inválido",
                                 f"O CPF '{cpf_para_validar}' parece ser inválido.\n"
                                 "Verifique os números e os dígitos verificadores.",
                                 parent=janela_cadastro_gui)
            print(f"ERRO (Cadastro): Validação falhou - CPF inválido (verificadores).")
            cpf_entry.focus_set() # Foca no campo CPF
            cpf_entry.selection_range(0, tk.END) # Seleciona o texto inválido
            return # Para o processo

        # Validação simples do E-mail
        email_para_validar = dados_coletados_cadastro["E-mail"]
        if "@" not in email_para_validar or "." not in email_para_validar: # Verifica básico: @ e .
             messagebox.showerror("E-mail Inválido",
                                  "O formato do E-mail parece inválido.\n"
                                  "Deve conter pelo menos '@' e '.'",
                                  parent=janela_cadastro_gui)
             print("ERRO (Cadastro): Validação falhou - E-mail inválido.")
             email_entry.focus_set()
             return # Para o processo

        # Validação de Unicidade do CPF: Verifica se já existe um registro com este CPF
        cpf_numeros_verificar = ''.join(filter(str.isdigit, cpf_para_validar))
        print(f"DEBUG (Cadastro): Verificando se CPF {cpf_numeros_verificar} já existe...")
        arquivo_existente_path, _ = find_record_file_by_cpf(cpf_numeros_verificar)
        if arquivo_existente_path:
            # Se encontrou um arquivo, o CPF já está cadastrado
            messagebox.showerror("CPF Já Cadastrado",
                                 f"Já existe um registro no sistema com o CPF {cpf_numeros_verificar}!\n"
                                 f"(Arquivo: ...\\{os.path.basename(os.path.dirname(arquivo_existente_path))}\\{os.path.basename(arquivo_existente_path)})\n"
                                 "Não é possível cadastrar o mesmo CPF novamente.",
                                 parent=janela_cadastro_gui)
            print(f"ERRO (Cadastro): Validação falhou - CPF {cpf_numeros_verificar} já existe.")
            cpf_entry.focus_set()
            cpf_entry.selection_range(0, tk.END)
            return # Para o processo

        # Se passou por todas as validações...
        print("DEBUG (Cadastro): Validação OK. Solicitando confirmação para salvar.")

        # Passo 3: Confirmação final com o usuário
        if messagebox.askyesno("Confirmar Novo Cadastro",
                               f"Confirma o cadastro deste novo registro de {tipo_registro_novo}?",
                               parent=janela_cadastro_gui):
            # Se usuário confirmou...
            print("INFO (Cadastro): Usuário confirmou. Tentando salvar...")
            # Tenta salvar os dados usando a função principal
            sucesso_salvar_cadastro = salvar_dados_individual(tipo_registro_novo, dados_coletados_cadastro)

            # Verifica o resultado do salvamento
            if sucesso_salvar_cadastro:
                messagebox.showinfo("Sucesso", f"{tipo_registro_novo} cadastrado com sucesso!", parent=None) # None para não bloquear fechar
                print(f"INFO (Cadastro): {tipo_registro_novo} cadastrado. Fechando janela.")
                janela_cadastro_gui.destroy() # Fecha a janela de cadastro
            else:
                # Se salvar falhou, a função salvar_dados_individual já mostrou o erro
                print("ERRO (Cadastro): A função salvar_dados_individual() retornou erro.")
        else:
            # Se usuário cancelou na confirmação
            print("INFO (Cadastro): Usuário cancelou o salvamento.")
            # Não faz nada, janela continua aberta


    # --- Criação dos Widgets da Interface Gráfica (Layout similar à edição) ---
    print("DEBUG (Cadastro): Criando widgets da janela de cadastro...")
    main_frame_cadastro = ttk.Frame(janela_cadastro_gui, padding="10")
    main_frame_cadastro.pack(expand=True, fill=tk.BOTH)

    row_num_cad = 0 # Contador de linha para o grid

    # Nome
    ttk.Label(main_frame_cadastro, text="Nome*:").grid(row=row_num_cad, column=0, sticky=tk.W, padx=5, pady=3)
    nome_entry = ttk.Entry(main_frame_cadastro, textvariable=nome_var, width=40)
    nome_entry.grid(row=row_num_cad, column=1, columnspan=2, padx=5, pady=3, sticky=tk.EW)
    nome_entry.focus_set() # Foco inicial
    row_num_cad += 1

    # Endereço
    ttk.Label(main_frame_cadastro, text="Endereço*:").grid(row=row_num_cad, column=0, sticky=tk.W, padx=5, pady=3)
    endereco_entry = ttk.Entry(main_frame_cadastro, textvariable=endereco_var, width=40)
    endereco_entry.grid(row=row_num_cad, column=1, columnspan=2, padx=5, pady=3, sticky=tk.EW)
    row_num_cad += 1

    # Cidade
    ttk.Label(main_frame_cadastro, text="Cidade*:").grid(row=row_num_cad, column=0, sticky=tk.W, padx=5, pady=3)
    cidade_entry = ttk.Entry(main_frame_cadastro, textvariable=cidade_var, width=30)
    cidade_entry.grid(row=row_num_cad, column=1, padx=5, pady=3, sticky=tk.W)
    row_num_cad += 1

    # Estado (Combobox)
    ttk.Label(main_frame_cadastro, text="Estado*:").grid(row=row_num_cad, column=0, sticky=tk.W, padx=5, pady=3)
    lista_estados_cad = ["AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"]
    estado_combo_cad = ttk.Combobox(main_frame_cadastro, textvariable=estado_var, values=lista_estados_cad, state="readonly", width=5)
    estado_combo_cad.grid(row=row_num_cad, column=1, padx=5, pady=3, sticky=tk.W)
    # Define um estado padrão selecionado (ex: SP) se a lista não estiver vazia
    if lista_estados_cad: estado_var.set("SP")
    row_num_cad += 1

    # CPF
    ttk.Label(main_frame_cadastro, text="CPF*:").grid(row=row_num_cad, column=0, sticky=tk.W, padx=5, pady=3)
    # Entry com validação para permitir apenas 11 dígitos
    cpf_entry = ttk.Entry(main_frame_cadastro, textvariable=cpf_var, width=15,
                          validate='key', validatecommand=validador_cpf_registrado_cmd)
    cpf_entry.grid(row=row_num_cad, column=1, padx=5, pady=3, sticky=tk.W)
    ttk.Label(main_frame_cadastro, text="(somente números)").grid(row=row_num_cad, column=2, sticky=tk.W, padx=0, pady=3) # Hint ao lado
    row_num_cad += 1

    # E-mail
    ttk.Label(main_frame_cadastro, text="E-mail*:").grid(row=row_num_cad, column=0, sticky=tk.W, padx=5, pady=3)
    email_entry = ttk.Entry(main_frame_cadastro, textvariable=email_var, width=40)
    email_entry.grid(row=row_num_cad, column=1, columnspan=2, padx=5, pady=3, sticky=tk.EW)
    row_num_cad += 1

    # Sexo (Radiobuttons)
    ttk.Label(main_frame_cadastro, text="Sexo*:").grid(row=row_num_cad, column=0, sticky=tk.W, padx=5, pady=3)
    sexo_frame_cad = ttk.Frame(main_frame_cadastro)
    sexo_frame_cad.grid(row=row_num_cad, column=1, columnspan=2, padx=5, pady=0, sticky=tk.W)
    ttk.Radiobutton(sexo_frame_cad, text="M", variable=sexo_var, value="Masculino").pack(side=tk.LEFT, padx=(0, 5))
    ttk.Radiobutton(sexo_frame_cad, text="F", variable=sexo_var, value="Feminino").pack(side=tk.LEFT, padx=(0, 5))
    ttk.Radiobutton(sexo_frame_cad, text="Outros", variable=sexo_var, value="Outro").pack(side=tk.LEFT)
    row_num_cad += 1

    # Atividades (Checkbuttons)
    ttk.Label(main_frame_cadastro, text="Atividades:").grid(row=row_num_cad, column=0, sticky=tk.NW, padx=5, pady=5)
    atividades_frame_cad = ttk.Frame(main_frame_cadastro)
    atividades_frame_cad.grid(row=row_num_cad, column=1, columnspan=2, padx=5, pady=3, sticky=tk.W)
    col_count_cad = 0
    row_count_cad = 0
    max_cols_cad = 3
    for i, nome_ativ_cad in enumerate(lista_atividades):
        # Usa o dicionário atividades_vars_dict que já foi criado
        chk_cad = ttk.Checkbutton(atividades_frame_cad, text=nome_ativ_cad, variable=atividades_vars_dict[nome_ativ_cad])
        chk_cad.grid(row=row_count_cad, column=col_count_cad, sticky=tk.W, padx=2, pady=1)
        col_count_cad += 1
        if col_count_cad >= max_cols_cad:
            col_count_cad = 0
            row_count_cad += 1
    row_num_cad += (row_count_cad + 1) # Atualiza a linha principal baseada em quantas linhas de checkboxes foram usadas

    # Observação (Text com Scrollbar)
    ttk.Label(main_frame_cadastro, text="Observação:").grid(row=row_num_cad, column=0, sticky=tk.NW, padx=5, pady=5)
    obs_frame_cad = ttk.Frame(main_frame_cadastro)
    obs_frame_cad.grid(row=row_num_cad, column=1, columnspan=2, padx=5, pady=5, sticky=tk.NSEW)
    observacao_entry = tk.Text(obs_frame_cad, height=4, width=38, wrap=tk.WORD)
    obs_scrollbar_cad = ttk.Scrollbar(obs_frame_cad, orient=tk.VERTICAL, command=observacao_entry.yview)
    observacao_entry.config(yscrollcommand=obs_scrollbar_cad.set)
    observacao_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    obs_scrollbar_cad.pack(side=tk.RIGHT, fill=tk.Y)
    row_num_cad += 1

    # --- Botões de Ação ---
    botoes_frame_cad = ttk.Frame(main_frame_cadastro)
    botoes_frame_cad.grid(row=row_num_cad, column=0, columnspan=3, pady=15)

    # Botão Salvar
    botao_salvar_cad = ttk.Button(botoes_frame_cad, text="Salvar Cadastro", command=_salvar_novo_registro)
    botao_salvar_cad.pack(side=tk.LEFT, padx=10)

    # Botão Cancelar
    botao_cancelar_cad = ttk.Button(botoes_frame_cad, text="Cancelar", command=janela_cadastro_gui.destroy)
    botao_cancelar_cad.pack(side=tk.LEFT, padx=10)
    row_num_cad += 1

    # --- Configuração de Expansão ---
    # Coluna 1 (widgets) expande horizontalmente
    main_frame_cadastro.grid_columnconfigure(1, weight=1)
    # Linha da Observação expande verticalmente
    # (row_num_cad - 3 porque adicionamos 1 após obs e 1 após botões, e queremos a linha da obs_frame)
    main_frame_cadastro.grid_rowconfigure(row_num_cad - 3, weight=1)

    print(f"DEBUG (Cadastro): Janela de cadastro para '{tipo_registro_novo}' criada e pronta.")
    # Fim da função janela_cadastro

# --- Menu Principal ---

def menu_principal(usuario_logado, tipo_usuario):
    """
    Cria e exibe a janela principal do sistema com menus, adaptada
    para o tipo de usuário logado.

    Args:
        usuario_logado (str): O nome do usuário que fez login.
        tipo_usuario (str): O role do usuário ('admin' ou 'employee').
    """
    print(f"DEBUG (Menu): Criando janela principal para usuário '{usuario_logado}' (Role: {tipo_usuario})")
    janela_principal = tk.Tk()
    janela_principal.minsize(450, 250) # Tamanho mínimo
    janela_principal.title(f"Sistema de Registros - Logado: {usuario_logado} ({tipo_usuario})")

    # --- Funções Auxiliares para Comandos do Menu (sem lambda) ---
    def _abrir_cadastro_aluno():
        print("DEBUG (Menu): Comando 'Novo Aluno...' selecionado.")
        janela_cadastro("Aluno")

    def _abrir_cadastro_funcionario():
        print("DEBUG (Menu): Comando 'Novo Funcionário...' selecionado.")
        janela_cadastro("Funcionário")

    def _abrir_cadastro_professor():
        print("DEBUG (Menu): Comando 'Novo Professor...' selecionado.")
        janela_cadastro("Professor")

    def _abrir_consulta_nome():
        print("DEBUG (Menu): Comando 'Consulta por Nome...' selecionado.")
        janela_consulta("nome")

    def _abrir_consulta_cpf():
        print("DEBUG (Menu): Comando 'Consulta por CPF...' selecionado.")
        janela_consulta("cpf")

    def _abrir_consulta_atividade():
        print("DEBUG (Menu): Comando 'Consulta por Atividade...' selecionado.")
        janela_consulta("atividade")

    def _iniciar_alteracao_wrapper():
        print("DEBUG (Menu): Comando 'Alterar Registro...' selecionado.")
        iniciar_alteracao_registro() # Chama a função principal de alteração

    # Wrapper para exclusão que passa o usuário logado
    def _excluir_cadastro_wrapper():
        print(f"DEBUG (Menu): Comando 'Excluir Cadastro...' selecionado. Usuário: {usuario_logado}")
        excluir_cadastro_por_cpf(usuario_logado) # Passa o usuário atual

    def _gerar_relatorio_wrapper():
        print("DEBUG (Menu): Comando 'Gerar Relatório Simples...' selecionado.")
        gerar_relatorio_simples()

    def _abrir_gerenciar_usuarios():
        print("DEBUG (Menu): Comando 'Gerenciar Usuários...' selecionado.")
        janela_gerenciar_usuarios()
    # --- Fim das Funções Auxiliares ---


    # --- Criação da Barra de Menu ---
    menu_barra = tk.Menu(janela_principal)
    janela_principal.config(menu=menu_barra)

    # --- Menu Cadastro ---
    cadastro_menu = tk.Menu(menu_barra, tearoff=0) # tearoff=0 impede destacar o menu
    menu_barra.add_cascade(label="Cadastro", menu=cadastro_menu)
    cadastro_menu.add_command(label="Novo Aluno...", command=_abrir_cadastro_aluno)
    cadastro_menu.add_command(label="Novo Funcionário...", command=_abrir_cadastro_funcionario)
    cadastro_menu.add_command(label="Novo Professor...", command=_abrir_cadastro_professor)

    # --- Menu Consulta ---
    consulta_menu = tk.Menu(menu_barra, tearoff=0)
    menu_barra.add_cascade(label="Consulta", menu=consulta_menu)
    consulta_menu.add_command(label="Por Nome...", command=_abrir_consulta_nome)
    consulta_menu.add_command(label="Por CPF...", command=_abrir_consulta_cpf)
    consulta_menu.add_command(label="Por Atividade...", command=_abrir_consulta_atividade)

    # --- Menu Administrativo ---
    administrativo_menu = tk.Menu(menu_barra, tearoff=0)
    menu_barra.add_cascade(label="Administrativo", menu=administrativo_menu)
    # Comandos disponíveis para todos (admin e employee)
    administrativo_menu.add_command(label="Alterar Registro por CPF...", command=_iniciar_alteracao_wrapper)
    administrativo_menu.add_command(label="Excluir Cadastro por CPF...", command=_excluir_cadastro_wrapper) # Wrapper passa o usuário
    administrativo_menu.add_separator()
    administrativo_menu.add_command(label="Gerar Relatório Simples...", command=_gerar_relatorio_wrapper)

    # Comandos SOMENTE para ADMIN
    if tipo_usuario == ADMIN_ROLE:
        print("DEBUG (Menu): Usuário é ADMIN, adicionando opção 'Gerenciar Usuários'.")
        administrativo_menu.add_separator()
        administrativo_menu.add_command(label="Gerenciar Usuários (Funcionários)...", command=_abrir_gerenciar_usuarios)
    # else:
    #    print("DEBUG (Menu): Usuário não é ADMIN, 'Gerenciar Usuários' não será adicionado.")


    # --- Conteúdo da Janela Principal ---
    main_frame_principal = ttk.Frame(janela_principal, padding="20")
    main_frame_principal.pack(expand=True, fill=tk.BOTH) # Expande com a janela

    # Mensagens de boas-vindas centralizadas
    ttk.Label(main_frame_principal, text=f"Bem-vindo(a), {usuario_logado}!",
              font=("Helvetica", 16)).pack(pady=(20, 10)) # pack centraliza por padrão
    ttk.Label(main_frame_principal, text="Utilize os menus acima para acessar as funcionalidades.",
              font=("Helvetica", 10)).pack(pady=(0, 20))

    # Botão para Sair do Sistema (fecha a janela principal)
    botao_sair = ttk.Button(main_frame_principal, text="Sair do Sistema", command=janela_principal.destroy)
    botao_sair.pack(pady=20, side=tk.BOTTOM) # Coloca na parte inferior

    # Configurações de expansão para centralizar o conteúdo
    # Faz a janela principal (linha 0, coluna 0) expandir
    janela_principal.rowconfigure(0, weight=1)
    janela_principal.columnconfigure(0, weight=1)
    # Faz o frame principal (linha 0, coluna 0 dentro da janela) expandir
    # main_frame_principal já está configurado com pack(expand=True, fill=BOTH)

    # Inicia o loop da janela principal
    print("DEBUG (Menu): Iniciando mainloop da janela principal.")
    janela_principal.mainloop()
    print("DEBUG (Menu): Mainloop da janela principal terminou (janela fechada).")

# --- Ponto de Entrada Principal da Aplicação ---
if __name__ == "__main__":
    print("===============================================")
    print("INFO: Iniciando Aplicação de Sistema de Registros...")
    print(f"INFO: Data e Hora Atual: {datetime.datetime.now()}")
    print(f"INFO: Pasta Base: {BASE_PATH}")
    print(f"INFO: Pasta da Aplicação: {APP_FOLDER_PATH}")
    print(f"INFO: Arquivo de Usuários: {USUARIOS_FILE_PATH}")
    print("===============================================")

    # Bloco principal de inicialização e execução
    try:
        # Passo 1: Verificar/criar a pasta principal da aplicação.
        # A função verificar_pasta_principal() já mostra erro crítico se falhar.
        print("INFO: Verificando pasta principal da aplicação...")
        if not verificar_pasta_principal():
            # Se falhou, a função já mostrou erro e retornou False. Encerrar.
            print("ERRO CRÍTICO: Falha ao verificar/criar a pasta principal. Aplicação será encerrada.")
            # Não precisa de messagebox aqui, a função já fez.
        else:
            # Pasta principal OK, continuar.
            print("INFO: Pasta principal OK.")
            # Passo 2: Verificar/criar/corrigir o arquivo de usuários (usuarios.txt)
            # A função verificar_criar_usuarios_file() garante que o ADM exista com hash/salt.
            print("INFO: Verificando arquivo de usuários...")
            if verificar_criar_usuarios_file():
                # Arquivo de usuários OK ou foi criado/corrigido.
                print("INFO: Arquivo de usuários OK. Iniciando a janela de login...")
                # Passo 3: Iniciar a interface gráfica pela janela de login.
                janela_login()
                # A execução continua aqui APÓS a janela de login ser fechada
                # (ou a janela principal ser fechada, se o login for bem-sucedido)
                print("INFO: Sistema finalizado pelo usuário ou janela fechada.")
            else:
                # Se houve um erro crítico ao verificar/criar o arquivo de usuários.
                # A função verificar_criar_usuarios_file() já deve ter mostrado o erro.
                print("ERRO CRÍTICO: Falha ao inicializar o arquivo de usuários. Aplicação será encerrada.")
                # Não precisa de messagebox aqui.

    except Exception as e_main:
        # Captura de erro genérica para qualquer falha inesperada no bloco principal
        print(f"ERRO CRÍTICO INESPERADO na inicialização: {type(e_main).__name__}: {e_main}")
        import traceback
        traceback.print_exc()
        # Tenta mostrar um erro final para o usuário
        try:
            root_err_main = tk.Tk()
            root_err_main.withdraw() # Esconde a janela raiz vazia
            messagebox.showerror("Erro Crítico Inesperado",
                                 f"Ocorreu um erro inesperado e fatal durante a inicialização da aplicação:\n"
                                 f"{type(e_main).__name__}: {e_main}\n\n"
                                 f"A aplicação será encerrada. Verifique os logs no console.")
            root_err_main.destroy()
        except Exception as e_msgbox:
            print(f"ERRO: Falha até ao mostrar a mensagem de erro final: {e_msgbox}")

    print("===============================================")
    print("INFO: Aplicação finalizada.")
    print("===============================================")
