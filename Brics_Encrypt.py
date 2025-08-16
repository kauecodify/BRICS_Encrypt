# BRICS_Encrypt - Sistema Financeiro Pós-Quântico BRICS
# Módulo Principal: transferencias_batch.py
# keys = cnpj ; cpf ; cell chinese ; email chinese ; uscc - china ; inn - rússia ; aadhaar - índia
# autarquia = edit and merge ;  

# =============================================================================

import time
from cryptography.hazmat.primitives.asymmetric import kyber, dilithium
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import hashlib
import json
from decimal import Decimal, ROUND_HALF_UP
 
# =============================================================================
 
# =============================================================================

# 1. gerenciamento de identificadores e dados de parceiros
class IdentificadorBRICS:
    @staticmethod
    def validar_identificador(identificador: str) -> str:
        """Valida e normaliza identificadores locais dos BRICS"""
        # CNPJ brasileiro (14 dígitos)
        if identificador.isdigit() and len(identificador) == 14:
            return f"BR:CNPJ:{identificador}"
        # CPF brasileiro (11 dígitos)
        elif identificador.isdigit() and len(identificador) == 11:
            return f"BR:CPF:{identificador}"
        # Celular chinês (11 dígitos)
        elif identificador.isdigit() and len(identificador) == 11:
            return f"CN:PHONE:{identificador}"
        # Email chinês
        elif "@" in identificador and (".cn" in identificador.split("@")[-1] or ".中国" in identificador):
            return f"CN:EMAIL:{identificador}"
        # USCC - Unified Social Credit Code (China)
        elif len(identificador) == 18 and identificador[:2].isalpha():
            return f"CN:USCC:{identificador}"
        # INN - Individual Taxpayer Number (Rússia)
        elif identificador.isdigit() and len(identificador) in (10, 12):
            return f"RU:INN:{identificador}"
        # Aadhaar (Índia)
        elif identificador.isdigit() and len(identificador) == 12:
            return f"IN:AADHAAR:{identificador}"
        else:
            raise ValueError("Identificador inválido")
 
# =============================================================================

# =============================================================================

# 2. parceiros BRICS-APEX
class ParceirosBRICS_APEX:
    RESERVAS = {
        "CNY": Decimal('5000000000000'),  # 5 trilhões de Yuan
        "RUB": Decimal('80000000000000'), # 80 trilhões de Rublos
        "BRL": Decimal('1000000000000'),  # 1 trilhão de Reais
        "INR": Decimal('40000000000000'), # 40 trilhões de Rúpias
        "ZAR": Decimal('3000000000000')   # 3 trilhões de Rand
    }
    
    TAXAS_OFICIAIS = {
        ("BRL", "CNY"): Decimal('1.20'),
        ("CNY", "BRL"): Decimal('0.83'),
        ("BRL", "RUB"): Decimal('15.40'),
        ("RUB", "BRL"): Decimal('0.065'), # >>> high-business and control (loop low)
        ("CNY", "RUB"): Decimal('12.83'), 
        ("RUB", "CNY"): Decimal('0.078'), # >>> high-business and control (loop low)
        ("BRL", "INR"): Decimal('16.50'),
        ("INR", "BRL"): Decimal('0.060'), # >>> high-business and control (loop low)
        ("CNY", "INR"): Decimal('13.75'),
        ("INR", "CNY"): Decimal('0.073'), # >>> high-business and control (loop low)
        ("BRL", "ZAR"): Decimal('3.10'),
        ("ZAR", "BRL"): Decimal('0.32'), # >>> high-business
        ("CNY", "ZAR"): Decimal('2.58'),
        ("ZAR", "CNY"): Decimal('0.39') # >>> high-business
    }

# =============================================================================

# =============================================================================

    @staticmethod
    def verificar_reserva_suficiente(moeda: str, valor: Decimal) -> bool:
        """Verifica se há reserva suficiente para a transação"""
        return valor <= ParceirosBRICS_APEX.RESERVAS[moeda]
    
    @staticmethod
    def atualizar_reserva(moeda: str, valor: Decimal, operacao: str):
        """Atualiza as reservas após transação (add ou remove)"""
        if operacao == "add":
            ParceirosBRICS_APEX.RESERVAS[moeda] += valor
        elif operacao == "sub":
            ParceirosBRICS_APEX.RESERVAS[moeda] -= valor

# =============================================================================

# =============================================================================

# 3. mecanismo de criptografia pós-quântica
class CriptografiaPQ:
    def __init__(self):
        self.kyber_priv_key, self.kyber_pub_key = self.gerar_chaves_kyber()
        self.dilithium_priv_key, self.dilithium_pub_key = self.gerar_chaves_dilithium()

    @staticmethod
    def gerar_chaves_kyber():
        priv_key = kyber.KyberPrivateKey.generate()
        pub_key = priv_key.public_key()
        return priv_key, pub_key

    @staticmethod
    def gerar_chaves_dilithium():
        priv_key = dilithium.DilithiumPrivateKey.generate()
        pub_key = priv_key.public_key()
        return priv_key, pub_key

    def assinar_transacao(self, dados: bytes) -> bytes:
        return self.dilithium_priv_key.sign(
            dados,
            algorithm=hashes.SHA3_512()
        )

    def verificar_assinatura(self, assinatura: bytes, dados: bytes, pub_key: bytes) -> bool:
        try:
            pub_key.verify(
                assinatura,
                dados,
                algorithm=hashes.SHA3_512()
            )
            return True
        except:
            return False

# =============================================================================

# =============================================================================

# 4. processador de transações em lote com verificação em tempo real a cada 10seg
class ProcessadorLoteBRICS:
    def __init__(self, intervalo_lote=10):
        self.fila_transacoes = []
        self.intervalo_lote = intervalo_lote  # 10 segundos
        self.ultimo_processamento = time.time()
        self.cripto = CriptografiaPQ()
        self.taxas_verificadas = {}

# =============================================================================

# =============================================================================

    def adicionar_transacao(self, origem: str, destino: str, valor: float, moeda: str):
        """Adiciona transação à fila com verificação local e em tempo real"""
        # validação em tempo real (<5s)
        inicio = time.time()
        
        # valida identificadores (incluindo novos tipos)
        origem_norm = IdentificadorBRICS.validar_identificador(origem)
        destino_norm = IdentificadorBRICS.validar_identificador(destino)
        
        # obtém moeda de destino para verificação de reservas
        moeda_dest = self.obter_moeda_destino(destino_norm)
        
        # pré-conversão para verificação em tempo real
        conversao = self.pre_converter_moeda(valor, moeda, moeda_dest)
        
        # verificação de reservas em tempo real
        if not ParceirosBRICS_APEX.verificar_reserva_suficiente(moeda_dest, conversao['valor_convertido']):
            raise ValueError(f"Reserva insuficiente de {moeda_dest} para transação")
        
        # Registra taxa verificada para uso posterior no lote (adc fechamento D-1)
        chave_taxa = f"{origem_norm}-{destino_norm}"
        self.taxas_verificadas[chave_taxa] = {
            "taxa": conversao['taxa'],
            "timestamp": time.time(),
            "validade": 15  # segundos
        }
        
        # cria transação com dados de pré-conversão
        transacao = {
            "timestamp": time.time(),
            "origem": origem_norm,
            "destino": destino_norm,
            "valor": Decimal(str(valor)),
            "valor_previsto": conversao['valor_convertido'],
            "moeda": moeda,
            "moeda_destino": moeda_dest,
            "taxa_prevista": conversao['taxa'],
            "assinatura": None
        }
        
        # assinar transação localmente
        dados_assinatura = json.dumps(transacao).encode()
        transacao["assinatura"] = self.cripto.assinar_transacao(dados_assinatura)
        
        self.fila_transacoes.append(transacao)
        
        tempo_processo = time.time() - inicio
        if tempo_processo > 5:
            print(f"AVISO: Transação próxima do limite PIX ({tempo_processo:.2f}s)")
        
        self.verificar_processamento()
        
# =============================================================================

# =============================================================================

    def verificar_processamento(self):
        """Processa lotes a cada 10s sem intervenção WAN"""
        tempo_atual = time.time()
        if tempo_atual - self.ultimo_processamento >= self.intervalo_lote:
            self.processar_lote()
            self.ultimo_processamento = tempo_atual

    def processar_lote(self):
        """Processa transações localmente sem WAN"""
        if not self.fila_transacoes:
            return
        
        print(f"\n--- INICIANDO PROCESSAMENTO DE LOTE ({len(self.fila_transacoes)} transações) ---")
        print(f"Reservas BRICS-APEX: CNY={ParceirosBRICS_APEX.RESERVAS['CNY']:.2f}, RUB={ParceirosBRICS_APEX.RESERVAS['RUB']:.2f}")
        
        # 1. verificar assinaturas
        transacoes_validas = []
        for transacao in self.fila_transacoes:
            dados = dict(transacao)
            assinatura = dados.pop("assinatura")
            dados_verificacao = json.dumps(dados).encode()
            
            if self.cripto.verificar_assinatura(
                assinatura,
                dados_verificacao,
                self.cripto.dilithium_pub_key
            ):
                transacoes_validas.append(transacao)
        
        # 2. verificar validade das taxas pré-calculadas
        transacoes_verificadas = self.verificar_taxas(transacoes_validas)
        
        # 3. conversão direta de moedas com reservas reais
        transacoes_processadas = self.converter_moedas(transacoes_verificadas)
        
        # 4. liquidação nas reservas BRICS-APEX
        self.liquidar_transacoes(transacoes_processadas)
        
        # limpar fila processada
        self.fila_transacoes = []
        print("--- LOTE PROCESSADO COM SUCESSO ---")

# =============================================================================

# =============================================================================

    def pre_converter_moeda(self, valor: float, de_moeda: str, para_moeda: str) -> dict:
        """Pré-conversão para verificação em tempo real"""
        chave_taxa = (de_moeda, para_moeda)
        if chave_taxa in ParceirosBRICS_APEX.TAXAS_OFICIAIS:
            taxa = ParceirosBRICS_APEX.TAXAS_OFICIAIS[chave_taxa]
            valor_conv = Decimal(str(valor)) * taxa
            return {
                "valor_convertido": valor_conv,
                "taxa": taxa
            }
        else:
            # conversão via USD (fallback)
            taxa_usd = Decimal('0.18')  # USD intermediário
            valor_conv = Decimal(str(valor)) * taxa_usd
            return {
                "valor_convertido": valor_conv,
                "taxa": taxa_usd
            }
# =============================================================================

# =============================================================================

    def verificar_taxas(self, transacoes: list) -> list:
        """Verifica se as taxas pré-calculadas ainda são válidas"""
        transacoes_validadas = []
        for transacao in transacoes:
            chave_taxa = f"{transacao['origem']}-{transacao['destino']}"
            taxa_verificada = self.taxas_verificadas.get(chave_taxa)
            
            # verifica se a taxa pré-calculada ainda é válida
            if taxa_verificada and (time.time() - taxa_verificada['timestamp']) <= taxa_verificada['validade']:
                transacao['taxa_aplicada'] = taxa_verificada['taxa']
                transacoes_validadas.append(transacao)
            else:
                # recalcula se a taxa expirou
                nova_taxa = self.pre_converter_moeda(
                    float(transacao['valor']),
                    transacao['moeda'],
                    transacao['moeda_destino']
                )['taxa']
                transacao['taxa_aplicada'] = nova_taxa
                transacoes_validadas.append(transacao)
                print(f"ATENÇÃO: Taxa recalculada para {transacao['origem']} -> {transacao['destino']}")
        
        return transacoes_validadas

# =============================================================================

# =============================================================================

    def converter_moedas(self, transacoes: list) -> list:
        """Conversão direta usando reservas BRICS-APEX"""
        for transacao in transacoes:
            taxa = transacao['taxa_aplicada']
            valor_convertido = transacao['valor'] * taxa
            
            # Arredondamento bancário (5+ dígitos)
            valor_convertido = valor_convertido.quantize(
                Decimal('0.00001'), 
                rounding=ROUND_HALF_UP
            )
            
            transacao['valor_convertido'] = valor_convertido
            transacao['diferenca_taxa'] = valor_convertido - transacao['valor_previsto']
        
        return transacoes

# =============================================================================

# =============================================================================

    @staticmethod
    def obter_moeda_destino(destino: str) -> str:
        """Determina moeda pelo prefixo do identificador"""
        if destino.startswith("BR:"): return "BRL"
        elif destino.startswith("CN:"): return "CNY"
        elif destino.startswith("RU:"): return "RUB"
        elif destino.startswith("IN:"): return "INR"
        elif destino.startswith("ZA:"): return "ZAR"
        return "USD"

    def liquidar_transacoes(self, transacoes: list):
        """Liquidação real nas reservas BRICS-APEX"""
        for transacao in transacoes:
            # Remove valor da moeda de origem
            ParceirosBRICS_APEX.atualizar_reserva(
                transacao['moeda'],
                transacao['valor'],
                "sub"
            )
            
            # adiciona valor convertido na moeda de destino
            ParceirosBRICS_APEX.atualizar_reserva(
                transacao['moeda_destino'],
                transacao['valor_convertido'],
                "add"
            )
            
            # gera comprovante
            comprovante = (
                f"COMPROVANTE BRICS-APEX\n"
                f"Origem: {transacao['origem']}\n"
                f"Destino: {transacao['destino']}\n"
                f"Valor: {transacao['valor']:.2f} {transacao['moeda']}\n"
                f"Conversão: {transacao['valor_convertido']:.5f} {transacao['moeda_destino']}\n"
                f"Taxa: 1 {transacao['moeda']} = {transacao['taxa_aplicada']} {transacao['moeda_destino']}\n"
                f"Diferença: {transacao['diferenca_taxa']:.5f}"
            )
            
            print(f"\n{comprovante}")
            print(f"Reservas atualizadas: "
                  f"{transacao['moeda']}={ParceirosBRICS_APEX.RESERVAS[transacao['moeda']]:.2f}, "
                  f"{transacao['moeda_destino']}={ParceirosBRICS_APEX.RESERVAS[transacao['moeda_destino']]:.2f}")

# =============================================================================

# =============================================================================

# 5. interface PIX BRICS com verificação em tempo real
class SistemaPIXBRICS:
    def __init__(self):
        self.processador = ProcessadorLoteBRICS()
    
    def iniciar_transferencia(self, origem: str, destino: str, valor: float, moeda: str):
        """Inicia transferência com validação em tempo real (<5s)"""
        try:
            inicio = time.time()
            
            # validação básica
            if valor <= 0:
                raise ValueError("Valor inválido")
            
            # normaliza identificadores
            origem_norm = IdentificadorBRICS.validar_identificador(origem)
            destino_norm = IdentificadorBRICS.validar_identificador(destino)
            
            # obtém moeda de destino
            moeda_dest = self.processador.obter_moeda_destino(destino_norm)
            
            # pré-conversão para feedback imediato
            conversao = self.processador.pre_converter_moeda(valor, moeda, moeda_dest)
            
            # feedback em tempo real
            tempo_processo = time.time() - inicio
            print(f"\nTransação aceita em {tempo_processo:.3f}s")
            print(f"Valor previsto: {conversao['valor_convertido']:.5f} {moeda_dest}")
            print(f"Taxa: 1 {moeda} = {conversao['taxa']} {moeda_dest}")
            
            # adiciona à fila de processamento em lote
            self.processador.adicionar_transacao(origem, destino, valor, moeda)
            
        except Exception as e:
            print(f"\nERRO NA TRANSAÇÃO: {str(e)}")

# =============================================================================

# =============================================================================
# =============================================================================
# =============================================================================
# --- EXECUÇÃO DE EXEMPLO ---
if __name__ == "__main__":
    pix = SistemaPIXBRICS()
    
    print("=== TESTES DE TRANSFERÊNCIA BRICS-APEX ===")
    
    # transações com diferentes identificadores
    pix.iniciar_transferencia("12345678901", "13987654321", 150.0, "BRL")      # CPF BR -> Celular CN
    pix.iniciar_transferencia("12345678000195", "user@domain.cn", 50000.0, "BRL") # CNPJ BR -> Email CN
    pix.iniciar_transferencia("user@company.中国", "98765432100", 2000.0, "CNY")  # Email CN -> CPF BR
    pix.iniciar_transferencia("913112345678901234", "13911223344", 3500.0, "CNY") # USCC CN -> Celular CN
    pix.iniciar_transferencia("123456789012", "5021234567", 10000.0, "RUB")       # Aadhaar IN -> INN RU
    
    # simular espera para processamento do lote
    print("\nAguardando processamento em lote...")
    time.sleep(12)
    
    # nova transação após processamento
    pix.iniciar_transferencia("55566677799", "user3@org.cn", 300.0, "BRL")
    
    # Forçar processamento final
    print("\nForçando processamento final...")
    time.sleep(2)
    pix.processador.processar_lote()
# =============================================================================
# =============================================================================
# =============================================================================

