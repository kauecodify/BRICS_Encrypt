# =============================================================================
# BRICS_Encrypt - Sistema Financeiro Pós-Quântico BRICS
# Módulo Principal: transferencias_batch.py
# Banco de Dados de Controle em Tempo Real
# =============================================================================

import time
import sqlite3
from cryptography.hazmat.primitives.asymmetric import kyber, dilithium
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import json
from decimal import Decimal, ROUND_HALF_UP
import threading
import queue
import os
from datetime import datetime

# =============================================================================
# 0. Configuração do Banco de Dados de Controle
# =============================================================================

class BancoDadosControle:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance.inicializar_db()
            return cls._instance
    
    def inicializar_db(self):
        self.conn = sqlite3.connect(':memory:', check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Tabela de transações
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS transacoes (
            id TEXT PRIMARY KEY,
            timestamp REAL,
            origem TEXT,
            destino TEXT,
            moeda_origem TEXT,
            moeda_destino TEXT,
            valor_origem REAL,
            valor_convertido REAL,
            taxa REAL,
            status TEXT,
            kyber_pub_hash TEXT,
            dilithium_pub_hash TEXT,
            assinatura TEXT,
            lote_id TEXT
        )
        ''')
        
        # Tabela de lotes
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS lotes (
            lote_id TEXT PRIMARY KEY,
            inicio REAL,
            fim REAL,
            transacoes INTEGER,
            status TEXT
        )
        ''')
        
        # Tabela de chaves criptográficas
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS chaves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            kyber_pub TEXT,
            dilithium_pub TEXT,
            kyber_priv_hash TEXT,
            dilithium_priv_hash TEXT
        )
        ''')
        
        self.conn.commit()
    
    def registrar_transacao(self, transacao_id, timestamp, origem, destino, 
                          moeda_origem, moeda_destino, valor_origem, 
                          valor_convertido, taxa, kyber_pub_hash, 
                          dilithium_pub_hash, assinatura):
        try:
            self.cursor.execute('''
            INSERT INTO transacoes (
                id, timestamp, origem, destino, moeda_origem, moeda_destino,
                valor_origem, valor_convertido, taxa, status, 
                kyber_pub_hash, dilithium_pub_hash, assinatura
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                transacao_id, timestamp, origem, destino, moeda_origem, moeda_destino,
                float(valor_origem), float(valor_convertido), float(taxa), 'PENDENTE',
                kyber_pub_hash, dilithium_pub_hash, assinatura.hex()
            ))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Erro ao registrar transação: {str(e)}")
            return False
    
    def atualizar_transacao(self, transacao_id, valor_convertido, taxa, status, lote_id=None):
        try:
            if lote_id:
                self.cursor.execute('''
                UPDATE transacoes 
                SET valor_convertido = ?, taxa = ?, status = ?, lote_id = ?
                WHERE id = ?
                ''', (float(valor_convertido), float(taxa), status, lote_id, transacao_id))
            else:
                self.cursor.execute('''
                UPDATE transacoes 
                SET valor_convertido = ?, taxa = ?, status = ?
                WHERE id = ?
                ''', (float(valor_convertido), float(taxa), status, transacao_id))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Erro ao atualizar transação: {str(e)}")
            return False
    
    def registrar_lote(self, lote_id, inicio, fim, transacoes, status):
        try:
            self.cursor.execute('''
            INSERT INTO lotes (lote_id, inicio, fim, transacoes, status)
            VALUES (?, ?, ?, ?, ?)
            ''', (lote_id, inicio, fim, transacoes, status))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Erro ao registrar lote: {str(e)}")
            return False
    
    def registrar_chave(self, timestamp, kyber_pub, dilithium_pub, 
                       kyber_priv_hash, dilithium_priv_hash):
        try:
            self.cursor.execute('''
            INSERT INTO chaves (timestamp, kyber_pub, dilithium_pub, 
                               kyber_priv_hash, dilithium_priv_hash)
            VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, kyber_pub, dilithium_pub, 
                  kyber_priv_hash, dilithium_priv_hash))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Erro ao registrar chave: {str(e)}")
            return False
    
    def obter_ultimas_transacoes(self, limite=10):
        self.cursor.execute('''
        SELECT * FROM transacoes 
        ORDER BY timestamp DESC 
        LIMIT ?
        ''', (limite,))
        return self.cursor.fetchall()
    
    def obter_ultimas_chaves(self, limite=5):
        self.cursor.execute('''
        SELECT * FROM chaves 
        ORDER BY timestamp DESC 
        LIMIT ?
        ''', (limite,))
        return self.cursor.fetchall()
    
    def obter_transacao_por_id(self, transacao_id):
        self.cursor.execute('''
        SELECT * FROM transacoes 
        WHERE id = ?
        ''', (transacao_id,))
        return self.cursor.fetchone()
    
    def obter_chave_por_id(self, chave_id):
        self.cursor.execute('''
        SELECT * FROM chaves 
        WHERE id = ?
        ''', (chave_id,))
        return self.cursor.fetchone()

# Inicializar banco de dados singleton
db_controle = BancoDadosControle()

# =============================================================================
# 1. Gerenciamento de Identificadores e Dados de Parceiros
# =============================================================================

class IdentificadorBRICS:
    @staticmethod
    def validar_identificador(identificador: str) -> str:
        # ... (o mesmo código anterior) ...

# =============================================================================
# 2. Dados dos Parceiros BRICS-APEX
# =============================================================================

class ParceirosBRICS_APEX:
    RESERVAS = {
        # ... (o mesmo código anterior) ...
    }
    
    TAXAS_OFICIAIS = {
        # ... (o mesmo código anterior) ...
    }
    
    @staticmethod
    def verificar_reserva_suficiente(moeda: str, valor: Decimal) -> bool:
        # ... (o mesmo código anterior) ...
    
    @staticmethod
    def atualizar_reserva(moeda: str, valor: Decimal, operacao: str):
        # ... (o mesmo código anterior) ...

# =============================================================================
# 3. Mecanismo de Criptografia Pós-Quântica
# =============================================================================

class CriptografiaPQ:
    def __init__(self, controle_db=None):
        self.kyber_priv_key, self.kyber_pub_key = self.gerar_chaves_kyber()
        self.dilithium_priv_key, self.dilithium_pub_key = self.gerar_chaves_dilithium()
        self.controle_db = controle_db
        self.registrar_chaves_db()

    def registrar_chaves_db(self):
        if self.controle_db:
            timestamp = time.time()
            kyber_pub = self.serializar_chave(self.kyber_pub_key)
            dilithium_pub = self.serializar_chave(self.dilithium_pub_key)
            kyber_priv_hash = hashlib.sha256(
                self.serializar_chave(self.kyber_priv_key, False).encode()
            ).hexdigest()
            dilithium_priv_hash = hashlib.sha256(
                self.serializar_chave(self.dilithium_priv_key, False).encode()
            ).hexdigest()
            
            self.controle_db.registrar_chave(
                timestamp, kyber_pub, dilithium_pub, 
                kyber_priv_hash, dilithium_priv_hash
            )

    @staticmethod
    def serializar_chave(chave, publica=True):
        """Serializa chave para formato legível"""
        if publica:
            return chave.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        else:
            return chave.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()

    @staticmethod
    def gerar_chaves_kyber():
        # ... (o mesmo código anterior) ...

    @staticmethod
    def gerar_chaves_dilithium():
        # ... (o mesmo código anterior) ...

    def assinar_transacao(self, dados: bytes) -> bytes:
        # ... (o mesmo código anterior) ...

    def verificar_assinatura(self, assinatura: bytes, dados: bytes, pub_key: bytes) -> bool:
        # ... (o mesmo código anterior) ...

# =============================================================================
# 4. Processador de Transações em Lote com Banco de Dados
# =============================================================================

class ProcessadorLoteBRICS:
    def __init__(self, intervalo_lote=10, controle_db=None):
        self.fila_transacoes = queue.Queue()
        self.intervalo_lote = intervalo_lote
        self.ultimo_processamento = time.time()
        self.controle_db = controle_db
        self.cripto = CriptografiaPQ(controle_db)
        self.taxas_verificadas = {}
        self.executando = True
        self.thread_processamento = threading.Thread(target=self._monitorar_processamento)
        self.thread_processamento.daemon = True
        self.thread_processamento.start()

    def _monitorar_processamento(self):
        while self.executando:
            tempo_atual = time.time()
            if tempo_atual - self.ultimo_processamento >= self.intervalo_lote:
                self.processar_lote()
                self.ultimo_processamento = tempo_atual
            time.sleep(1)

    def adicionar_transacao(self, origem: str, destino: str, valor: float, moeda: str):
        # ... (código similar ao anterior até a criação da transação) ...
        
        # Gerar ID único para transação
        transacao_id = hashlib.sha256(
            f"{origem}{destino}{valor}{moeda}{time.time()}".encode()
        ).hexdigest()[:20]
        
        # Registrar no banco de dados
        kyber_pub_hash = hashlib.sha256(
            self.cripto.serializar_chave(self.cripto.kyber_pub_key).encode()
        ).hexdigest()[:12]
        
        dilithium_pub_hash = hashlib.sha256(
            self.cripto.serializar_chave(self.cripto.dilithium_pub_key).encode()
        ).hexdigest()[:12]
        
        self.controle_db.registrar_transacao(
            transacao_id=transacao_id,
            timestamp=time.time(),
            origem=origem_norm,
            destino=destino_norm,
            moeda_origem=moeda,
            moeda_destino=moeda_dest,
            valor_origem=valor,
            valor_convertido=conversao['valor_convertido'],
            taxa=conversao['taxa'],
            kyber_pub_hash=kyber_pub_hash,
            dilithium_pub_hash=dilithium_pub_hash,
            assinatura=assinatura
        )
        
        # Adicionar à fila com ID
        transacao["id"] = transacao_id
        self.fila_transacoes.put(transacao)
        
        # ... (restante do código) ...

    def processar_lote(self):
        if self.fila_transacoes.empty():
            return
        
        lote_id = f"LOTE-{time.time()}"
        transacoes = []
        while not self.fila_transacoes.empty():
            transacoes.append(self.fila_transacoes.get())
        
        print(f"\n--- INICIANDO PROCESSAMENTO DE LOTE {lote_id} ({len(transacoes)} transações) ---")
        
        # ... (processamento similar ao anterior) ...
        
        # Atualizar banco de dados
        for transacao in transacoes_processadas:
            self.controle_db.atualizar_transacao(
                transacao_id=transacao["id"],
                valor_convertido=transacao["valor_convertido"],
                taxa=transacao["taxa_aplicada"],
                status="PROCESSADO",
                lote_id=lote_id
            )
        
        # Registrar lote no banco de dados
        self.controle_db.registrar_lote(
            lote_id=lote_id,
            inicio=inicio_lote,
            fim=time.time(),
            transacoes=len(transacoes_processadas),
            status="CONCLUIDO"
        )
        
        print("--- LOTE PROCESSADO COM SUCESSO ---")

    # ... (outros métodos permanecem similares) ...

# =============================================================================
# 5. Interface de Controle em Tempo Real
# =============================================================================

class InterfaceControleTempoReal:
    def __init__(self, controle_db):
        self.controle_db = controle_db
        self.executando = True
        self.ultima_atualizacao = 0
    
    def iniciar_monitoramento(self, intervalo=3):
        """Inicia a interface de monitoramento em tempo real"""
        print("\n=== INICIANDO MONITORAMENTO EM TEMPO REAL ===")
        print("Pressione Ctrl+C para retornar ao menu\n")
        
        try:
            while self.executando:
                os.system('cls' if os.name == 'nt' else 'clear')
                self.exibir_painel_controle()
                time.sleep(intervalo)
        except KeyboardInterrupt:
            print("\nMonitoramento encerrado")
    
    def exibir_painel_controle(self):
        """Exibe o painel de controle com informações atualizadas"""
        # Obter dados do banco
        transacoes = self.controle_db.obter_ultimas_transacoes(5)
        chaves = self.controle_db.obter_ultimas_chaves(2)
        
        # Cabeçalho
        print(f"\n{'='*60}")
        print(f"BRICS_ENCRYPT - PAINEL DE CONTROLE EM TEMPO REAL")
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        # Últimas chaves criptográficas
        print("=== ÚLTIMAS CHAVES CRIPTOGRÁFICAS ===")
        for chave in chaves:
            ts = datetime.fromtimestamp(chave[1]).strftime('%H:%M:%S')
            print(f"[{ts}] KYBER: {chave[3][:12]}... DILITHIUM: {chave[4][:12]}...")
        print()
        
        # Últimas transações
        print("=== ÚLTIMAS TRANSAÇÕES ===")
        print(f"{'ID':<10} {'ORIGEM':<15} {'DESTINO':<15} {'VALOR':<10} {'STATUS':<12}")
        print("-" * 60)
        for trans in transacoes:
            origem_short = trans[2].split(':')[-1][:12] + '...' if len(trans[2]) > 12 else trans[2]
            destino_short = trans[3].split(':')[-1][:12] + '...' if len(trans[3]) > 12 else trans[3]
            valor_str = f"{trans[6]:.2f} {trans[4]} → {trans[7]:.2f} {trans[5]}"
            print(f"{trans[0][:8]:<10} {origem_short:<15} {destino_short:<15} {valor_str:<20} {trans[9]:<12}")
        
        # Estatísticas
        print("\n=== ESTATÍSTICAS ===")
        self.cursor.execute("SELECT COUNT(*) FROM transacoes WHERE status = 'PENDENTE'")
        pendentes = self.cursor.fetchone()[0]
        self.cursor.execute("SELECT COUNT(*) FROM transacoes WHERE status = 'PROCESSADO'")
        processadas = self.cursor.fetchone()[0]
        
        print(f"Transações Pendentes: {pendentes}")
        print(f"Transações Processadas: {processadas}")
        
        # Atualizar reservas
        print("\n=== RESERVAS BRICS-APEX ===")
        print(f"CNY: {ParceirosBRICS_APEX.RESERVAS['CNY']:,.2f}")
        print(f"RUB: {ParceirosBRICS_APEX.RESERVAS['RUB']:,.2f}")
        print(f"BRL: {ParceirosBRICS_APEX.RESERVAS['BRL']:,.2f}")
        print(f"INR: {ParceirosBRICS_APEX.RESERVAS['INR']:,.2f}")
        print(f"ZAR: {ParceirosBRICS_APEX.RESERVAS['ZAR']:,.2f}")
        
        print(f"\n{'='*60}")
        print("Atualizando a cada 3 segundos...")

# =============================================================================
# 6. Sistema PIX BRICS com Controle
# =============================================================================

class SistemaPIXBRICS:
    def __init__(self, controle_db):
        self.controle_db = controle_db
        self.processador = ProcessadorLoteBRICS(controle_db=controle_db)
    
    def iniciar_transferencia(self, origem: str, destino: str, valor: float, moeda: str):
        # ... (código similar ao anterior) ...
        
        # Feedback com ID de transação
        print(f"ID Transação: {transacao_id}")
        print(f"Chaves: KYBER:{kyber_pub_hash} DILITHIUM:{dilithium_pub_hash}")

# =============================================================================
# Menu Principal Aprimorado
# =============================================================================

if __name__ == "__main__":
    # Inicializar sistema com banco de dados
    pix = SistemaPIXBRICS(db_controle)
    controle_tempo_real = InterfaceControleTempoReal(db_controle)
    
    while True:
        print("\n=== SISTEMA BRICS_ENCRYPT ===")
        print("1. Executar transações de teste")
        print("2. Monitorar em tempo real")
        print("3. Ver detalhes de transação")
        print("4. Ver detalhes de chave criptográfica")
        print("5. Gerar novo par de chaves")
        print("6. Sair")
        
        escolha = input("Selecione uma opção: ")
        
        if escolha == "1":
            print("\nExecutando transações de teste...")
            pix.iniciar_transferencia("12345678901", "13987654321", 150.0, "BRL")
            pix.iniciar_transferencia("12345678000195", "user@domain.cn", 50000.0, "BRL")
            pix.iniciar_transferencia("user@company.中国", "98765432100", 2000.0, "CNY")
            pix.iniciar_transferencia("913112345678901234", "13911223344", 3500.0, "CNY")
            pix.iniciar_transferencia("123456789012", "5021234567", 10000.0, "RUB")
            pix.iniciar_transferencia("55566677799", "user3@org.cn", 300.0, "BRL")
            
            print("\nTransações enviadas para processamento em lote...")
            time.sleep(12)
            
        elif escolha == "2":
            controle_tempo_real.iniciar_monitoramento()
            
        elif escolha == "3":
            transacao_id = input("Digite o ID da transação: ")
            transacao = db_controle.obter_transacao_por_id(transacao_id)
            if transacao:
                print("\n=== DETALHES DA TRANSAÇÃO ===")
                print(f"ID: {transacao[0]}")
                print(f"Timestamp: {datetime.fromtimestamp(transacao[1])}")
                print(f"Origem: {transacao[2]}")
                print(f"Destino: {transacao[3]}")
                print(f"Moeda Origem: {transacao[4]}")
                print(f"Moeda Destino: {transacao[5]}")
                print(f"Valor Original: {transacao[6]:.2f}")
                print(f"Valor Convertido: {transacao[7]:.2f}")
                print(f"Taxa: {transacao[8]}")
                print(f"Status: {transacao[9]}")
                print(f"Hash KYBER: {transacao[10]}")
                print(f"Hash DILITHIUM: {transacao[11]}")
                print(f"Lote: {transacao[13]}")
            else:
                print("Transação não encontrada!")
                
        elif escolha == "4":
            chave_id = input("Digite o ID da chave: ")
            chave = db_controle.obter_chave_por_id(chave_id)
            if chave:
                print("\n=== DETALHES DA CHAVE ===")
                print(f"ID: {chave[0]}")
                print(f"Timestamp: {datetime.fromtimestamp(chave[1])}")
                print("\nChave Pública KYBER:")
                print(chave[2][:200] + "...")
                print("\nChave Pública DILITHIUM:")
                print(chave[3][:200] + "...")
                print(f"\nHash KYBER Priv: {chave[4]}")
                print(f"Hash DILITHIUM Priv: {chave[5]}")
            else:
                print("Chave não encontrada!")
                
        elif escolha == "5":
            print("\nGerando novas chaves criptográficas...")
            pix.processador.cripto = CriptografiaPQ(db_controle)
            print("Novas chaves geradas e registradas no banco de dados!")
            
        elif escolha == "6":
            pix.processador.executando = False
            print("Encerrando sistema...")
            break
            
        else:
            print("Opção inválida. Tente novamente.")

# =============================================================================
# Fim do Sistema
# =============================================================================