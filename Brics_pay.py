# -*- coding: utf-8 -*-
"""
brics_encrypt_db
pip install PyQt5 cryptography
"""
# BRICS_Encrypt - Sistema Financeiro Pós-Quântico BRICS
# Módulo Principal: transferencias_batch.py
# autarquia = edit and merge ;  
# Interface PyQt5: BRICS-PAY >> db

import sys
import time
from cryptography.hazmat.primitives.asymmetric import kyber, dilithium
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import json
from decimal import Decimal, ROUND_HALF_UP
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget, 
                            QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
                            QGroupBox, QFormLayout, QMessageBox, QProgressBar)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont, QColor

# =============================================================================
# 1. Gerenciamento de Identificadores e Dados de Parceiros
# =============================================================================

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
# 2. Dados dos Parceiros BRICS-APEX
# =============================================================================

class ParceirosBRICS_APEX:
    RESERVAS = {
        "CNY": Decimal('5000000000000'),  # 5 trilhões de Yuan
        "RUB": Decimal('80000000000000'), # 80 trilhões de Rublos
        "BRL": Decimal('1000000000000'),  # 1 trilhão de Reais
        "INR": Decimal('40000000000000'), # 40 trilhões de Rúpias
        "ZAR": Decimal('3000000000000')   # 3 trilhões de Rand
    }
    
    # buscar fechamento do dia anterior
    TAXAS_OFICIAIS = {
        ("BRL", "CNY"): Decimal('1.20'),
        ("CNY", "BRL"): Decimal('0.83'),
        ("BRL", "RUB"): Decimal('15.40'),
        ("RUB", "BRL"): Decimal('0.065'),
        ("CNY", "RUB"): Decimal('12.83'), 
        ("RUB", "CNY"): Decimal('0.078'),
        ("BRL", "INR"): Decimal('16.50'),
        ("INR", "BRL"): Decimal('0.060'),
        ("CNY", "INR"): Decimal('13.75'),
        ("INR", "CNY"): Decimal('0.073'),
        ("BRL", "ZAR"): Decimal('3.10'),
        ("ZAR", "BRL"): Decimal('0.32'),
        ("CNY", "ZAR"): Decimal('2.58'),
        ("ZAR", "CNY"): Decimal('0.39')
    }
    
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
# 3. Mecanismo de Criptografia Pós-Quântica
# =============================================================================

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
    
    def serializar_chave_publica(self, chave):
        return chave.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    def hash_chave_privada(self, chave):
        priv_bytes = chave.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return hashlib.sha256(priv_bytes).hexdigest()

# =============================================================================
# 4. Processador de Transações em Lote
# =============================================================================

class ProcessadorLoteBRICS:
    def __init__(self, intervalo_lote=10):
        self.fila_transacoes = []
        self.intervalo_lote = intervalo_lote
        self.ultimo_processamento = time.time()
        self.cripto = CriptografiaPQ()
        self.taxas_verificadas = {}
        self.historico_transacoes = []

    def adicionar_transacao(self, origem: str, destino: str, valor: float, moeda: str):
        """Adiciona transação à fila com verificação local e em tempo real"""
        try:
            inicio = time.time()
            
            origem_norm = IdentificadorBRICS.validar_identificador(origem)
            destino_norm = IdentificadorBRICS.validar_identificador(destino)
            moeda_dest = self.obter_moeda_destino(destino_norm)
            
            conversao = self.pre_converter_moeda(valor, moeda, moeda_dest)
            
            if not ParceirosBRICS_APEX.verificar_reserva_suficiente(moeda_dest, conversao['valor_convertido']):
                raise ValueError(f"Reserva insuficiente de {moeda_dest}")
            
            chave_taxa = f"{origem_norm}-{destino_norm}"
            self.taxas_verificadas[chave_taxa] = {
                "taxa": conversao['taxa'],
                "timestamp": time.time(),
                "validade": 15
            }
            
            transacao = {
                "id": hashlib.sha256(f"{time.time()}{origem}{destino}".encode()).hexdigest()[:12],
                "timestamp": time.time(),
                "origem": origem_norm,
                "destino": destino_norm,
                "valor": Decimal(str(valor)),
                "valor_previsto": conversao['valor_convertido'],
                "moeda": moeda,
                "moeda_destino": moeda_dest,
                "taxa_prevista": conversao['taxa'],
                "assinatura": None,
                "status": "Pendente"
            }
            
            dados_assinatura = json.dumps(transacao).encode()
            transacao["assinatura"] = self.cripto.assinar_transacao(dados_assinatura).hex()
            
            self.fila_transacoes.append(transacao)
            
            tempo_processo = time.time() - inicio
            return transacao, tempo_processo
            
        except Exception as e:
            raise e

    def verificar_processamento(self):
        tempo_atual = time.time()
        if tempo_atual - self.ultimo_processamento >= self.intervalo_lote:
            self.processar_lote()
            self.ultimo_processamento = tempo_atual
            return True
        return False

    def processar_lote(self):
        if not self.fila_transacoes:
            return
        
        transacoes_processadas = []
        for transacao in self.fila_transacoes:
            try:
                # Simulação de processamento
                transacao['status'] = "Processado"
                transacao['taxa_aplicada'] = self.taxas_verificadas.get(
                    f"{transacao['origem']}-{transacao['destino']}", {}
                ).get('taxa', transacao['taxa_prevista'])
                
                valor_convertido = transacao['valor'] * transacao['taxa_aplicada']
                transacao['valor_convertido'] = valor_convertido.quantize(
                    Decimal('0.00001'), rounding=ROUND_HALF_UP
                )
                
                # Atualizar reservas
                ParceirosBRICS_APEX.atualizar_reserva(
                    transacao['moeda'], transacao['valor'], "sub"
                )
                ParceirosBRICS_APEX.atualizar_reserva(
                    transacao['moeda_destino'], transacao['valor_convertido'], "add"
                )
                
                transacoes_processadas.append(transacao)
            except Exception as e:
                transacao['status'] = f"Erro: {str(e)}"
        
        self.historico_transacoes.extend(transacoes_processadas)
        self.fila_transacoes = []
        
        return transacoes_processadas

    def pre_converter_moeda(self, valor: float, de_moeda: str, para_moeda: str) -> dict:
        chave_taxa = (de_moeda, para_moeda)
        if chave_taxa in ParceirosBRICS_APEX.TAXAS_OFICIAIS:
            taxa = ParceirosBRICS_APEX.TAXAS_OFICIAIS[chave_taxa]
            valor_conv = Decimal(str(valor)) * taxa
            return {"valor_convertido": valor_conv, "taxa": taxa}
        else:
            taxa_usd = Decimal('0.18')
            return {"valor_convertido": Decimal(str(valor)) * taxa_usd, "taxa": taxa_usd}

    @staticmethod
    def obter_moeda_destino(destino: str) -> str:
        if destino.startswith("BR:"): return "BRL"
        elif destino.startswith("CN:"): return "CNY"
        elif destino.startswith("RU:"): return "RUB"
        elif destino.startswith("IN:"): return "INR"
        elif destino.startswith("ZA:"): return "ZAR"
        return "USD"

# =============================================================================
# 5. Interface PyQt5 - BRICS-PAY
# =============================================================================

class BRICSPayApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.processador = ProcessadorLoteBRICS()
        self.initUI()
        self.setup_timers()
        
    def initUI(self):
        self.setWindowTitle('BRICS-PAY - Sistema de Pagamentos Pós-Quântico')
        self.setGeometry(100, 100, 1200, 800)
        
        # Layout principal
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Tabs
        self.tabs = QTabWidget()
        
        # Tab 1: Realizar Transferência
        self.tab_transfer = QWidget()
        self.setup_transfer_tab()
        self.tabs.addTab(self.tab_transfer, "Transferência")
        
        # Tab 2: Transações
        self.tab_transactions = QWidget()
        self.setup_transactions_tab()
        self.tabs.addTab(self.tab_transactions, "Transações")
        
        # Tab 3: Reservas BRICS
        self.tab_reserves = QWidget()
        self.setup_reserves_tab()
        self.tabs.addTab(self.tab_reserves, "Reservas BRICS")
        
        # Tab 4: Chaves Criptográficas
        self.tab_keys = QWidget()
        self.setup_keys_tab()
        self.tabs.addTab(self.tab_keys, "Segurança")
        
        main_layout.addWidget(self.tabs)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Barra de status
        self.status_bar = self.statusBar()
        self.status_label = QLabel("Sistema pronto")
        self.status_bar.addWidget(self.status_label)
        
        # Progresso do lote
        self.lote_progress = QProgressBar()
        self.lote_progress.setRange(0, 10)
        self.lote_progress.setValue(0)
        self.status_bar.addPermanentWidget(self.lote_progress)
        
        # Atualizar UI
        self.atualizar_reservas()
        self.atualizar_chaves()
        
    def setup_timers(self):
        self.timer_lote = QTimer(self)
        self.timer_lote.timeout.connect(self.verificar_lotes)
        self.timer_lote.start(1000)  # Verificar a cada 1 segundo
        
    def verificar_lotes(self):
        tempo_restante = max(0, 10 - (time.time() - self.processador.ultimo_processamento))
        self.lote_progress.setValue(int(10 - tempo_restante))
        
        if self.processador.verificar_processamento():
            transacoes_processadas = self.processador.processar_lote()
            self.atualizar_transacoes()
            self.atualizar_reservas()
            self.status_label.setText(f"Lote processado: {len(transacoes_processadas)} transações")
            
    def setup_transfer_tab(self):
        layout = QVBoxLayout()
        
        # Grupo: Dados da Transferência
        group_transfer = QGroupBox("Realizar Transferência")
        form_layout = QFormLayout()
        
        self.input_origem = QLineEdit()
        self.input_origem.setPlaceholderText("CPF, CNPJ, Celular, Email...")
        form_layout.addRow("Identificador de Origem:", self.input_origem)
        
        self.input_destino = QLineEdit()
        self.input_destino.setPlaceholderText("CPF, CNPJ, Celular, Email...")
        form_layout.addRow("Identificador de Destino:", self.input_destino)
        
        self.input_valor = QLineEdit()
        self.input_valor.setPlaceholderText("0.00")
        form_layout.addRow("Valor:", self.input_valor)
        
        self.combo_moeda = QComboBox()
        self.combo_moeda.addItems(["BRL", "CNY", "RUB", "INR", "ZAR"])
        form_layout.addRow("Moeda:", self.combo_moeda)
        
        btn_transferir = QPushButton("Realizar Transferência")
        btn_transferir.clicked.connect(self.realizar_transferencia)
        btn_transferir.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        
        form_layout.addRow(btn_transferir)
        group_transfer.setLayout(form_layout)
        
        # Grupo: Resultado
        group_result = QGroupBox("Resultado da Transação")
        result_layout = QVBoxLayout()
        
        self.label_result = QLabel("Preencha os dados e clique em Transferir")
        self.label_result.setWordWrap(True)
        
        self.text_comprovante = QTextEdit()
        self.text_comprovante.setReadOnly(True)
        self.text_comprovante.setStyleSheet("font-family: monospace;")
        
        result_layout.addWidget(self.label_result)
        result_layout.addWidget(self.text_comprovante)
        group_result.setLayout(result_layout)
        
        layout.addWidget(group_transfer)
        layout.addWidget(group_result)
        self.tab_transfer.setLayout(layout)
    
    def setup_transactions_tab(self):
        layout = QVBoxLayout()
        
        # Tabela de transações pendentes
        group_pending = QGroupBox("Transações Pendentes")
        pending_layout = QVBoxLayout()
        
        self.table_pending = QTableWidget()
        self.table_pending.setColumnCount(6)
        self.table_pending.setHorizontalHeaderLabels(["ID", "Origem", "Destino", "Valor", "Moeda", "Status"])
        self.table_pending.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        pending_layout.addWidget(self.table_pending)
        group_pending.setLayout(pending_layout)
        
        # Tabela de histórico
        group_history = QGroupBox("Histórico de Transações")
        history_layout = QVBoxLayout()
        
        self.table_history = QTableWidget()
        self.table_history.setColumnCount(8)
        self.table_history.setHorizontalHeaderLabels(["ID", "Data", "Origem", "Destino", "Valor", "Convertido", "Moeda", "Status"])
        self.table_history.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        history_layout.addWidget(self.table_history)
        group_history.setLayout(history_layout)
        
        layout.addWidget(group_pending)
        layout.addWidget(group_history)
        self.tab_transactions.setLayout(layout)
    
    def setup_reserves_tab(self):
        layout = QVBoxLayout()
        
        # Atualizar reservas
        btn_atualizar = QPushButton("Atualizar Reservas")
        btn_atualizar.clicked.connect(self.atualizar_reservas)
        
        # Tabela de reservas
        self.table_reserves = QTableWidget()
        self.table_reserves.setColumnCount(2)
        self.table_reserves.setHorizontalHeaderLabels(["Moeda", "Reserva"])
        self.table_reserves.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Tabela de taxas
        group_taxas = QGroupBox("Taxas de Conversão Oficiais")
        taxas_layout = QVBoxLayout()
        
        self.table_taxas = QTableWidget()
        self.table_taxas.setColumnCount(3)
        self.table_taxas.setHorizontalHeaderLabels(["De", "Para", "Taxa"])
        self.table_taxas.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        taxas_layout.addWidget(self.table_taxas)
        group_taxas.setLayout(taxas_layout)
        
        layout.addWidget(btn_atualizar)
        layout.addWidget(self.table_reserves)
        layout.addWidget(group_taxas)
        self.tab_reserves.setLayout(layout)
    
    def setup_keys_tab(self):
        layout = QVBoxLayout()
        
        # Grupo: Chaves Atuais
        group_keys = QGroupBox("Chaves Criptográficas Atuais")
        keys_layout = QFormLayout()
        
        self.label_kyber_pub = QLabel()
        self.label_kyber_pub.setTextInteractionFlags(Qt.TextSelectableByMouse)
        keys_layout.addRow("Chave Pública Kyber:", self.label_kyber_pub)
        
        self.label_dilithium_pub = QLabel()
        self.label_dilithium_pub.setTextInteractionFlags(Qt.TextSelectableByMouse)
        keys_layout.addRow("Chave Pública Dilithium:", self.label_dilithium_pub)
        
        self.label_kyber_priv_hash = QLabel()
        self.label_kyber_priv_hash.setTextInteractionFlags(Qt.TextSelectableByMouse)
        keys_layout.addRow("Hash Chave Privada Kyber:", self.label_kyber_priv_hash)
        
        self.label_dilithium_priv_hash = QLabel()
        self.label_dilithium_priv_hash.setTextInteractionFlags(Qt.TextSelectableByMouse)
        keys_layout.addRow("Hash Chave Privada Dilithium:", self.label_dilithium_priv_hash)
        
        btn_atualizar = QPushButton("Atualizar Chaves")
        btn_atualizar.clicked.connect(self.atualizar_chaves)
        keys_layout.addRow(btn_atualizar)
        
        group_keys.setLayout(keys_layout)
        
        # Grupo: Informações de Segurança
        group_info = QGroupBox("Informações de Segurança")
        info_layout = QVBoxLayout()
        
        info_text = QLabel(
            "<b>Proteção Pós-Quântica:</b><br>"
            "- Kyber: Algoritmo de troca de chaves (KEM)<br>"
            "- Dilithium: Algoritmo de assinatura digital<br>"
            "<b>Proteções Adicionais:</b><br>"
            "- Todas as transações são assinadas digitalmente<br>"
            "- Chaves privadas nunca são armazenadas ou transmitidas<br>"
            "- Processamento em lotes isolado"
        )
        info_text.setWordWrap(True)
        
        info_layout.addWidget(info_text)
        group_info.setLayout(info_layout)
        
        layout.addWidget(group_keys)
        layout.addWidget(group_info)
        self.tab_keys.setLayout(layout)
    
    def realizar_transferencia(self):
        origem = self.input_origem.text().strip()
        destino = self.input_destino.text().strip()
        valor_text = self.input_valor.text().strip()
        moeda = self.combo_moeda.currentText()
        
        if not origem or not destino or not valor_text:
            QMessageBox.warning(self, "Dados Incompletos", "Preencha todos os campos!")
            return
            
        try:
            valor = float(valor_text)
            if valor <= 0:
                raise ValueError("Valor deve ser positivo")
            
            transacao, tempo = self.processador.adicionar_transacao(origem, destino, valor, moeda)
            
            # Atualizar UI
            self.atualizar_transacoes()
            self.input_origem.clear()
            self.input_destino.clear()
            self.input_valor.clear()
            
            # Mostrar comprovante
            comprovante = (
                f"TRANSFERÊNCIA REALIZADA COM SUCESSO!\n"
                f"Tempo de processamento: {tempo:.3f}s\n\n"
                f"ID: {transacao['id']}\n"
                f"Origem: {transacao['origem']}\n"
                f"Destino: {transacao['destino']}\n"
                f"Valor: {transacao['valor']:.2f} {transacao['moeda']}\n"
                f"Valor Previsto: {transacao['valor_previsto']:.5f} {transacao['moeda_destino']}\n"
                f"Taxa: 1 {transacao['moeda']} = {transacao['taxa_prevista']} {transacao['moeda_destino']}\n"
                f"Status: {transacao['status']}"
            )
            
            self.text_comprovante.setText(comprovante)
            self.label_result.setText("Transferência realizada com sucesso!")
            self.label_result.setStyleSheet("color: green; font-weight: bold;")
            
        except Exception as e:
            self.label_result.setText(f"Erro na transferência: {str(e)}")
            self.label_result.setStyleSheet("color: red; font-weight: bold;")
            self.text_comprovante.clear()
    
    def atualizar_transacoes(self):
        # Transações pendentes
        self.table_pending.setRowCount(len(self.processador.fila_transacoes))
        for row, trans in enumerate(self.processador.fila_transacoes):
            self.table_pending.setItem(row, 0, QTableWidgetItem(trans['id']))
            self.table_pending.setItem(row, 1, QTableWidgetItem(trans['origem']))
            self.table_pending.setItem(row, 2, QTableWidgetItem(trans['destino']))
            self.table_pending.setItem(row, 3, QTableWidgetItem(f"{trans['valor']:.2f}"))
            self.table_pending.setItem(row, 4, QTableWidgetItem(trans['moeda']))
            
            status_item = QTableWidgetItem(trans['status'])
            if "Erro" in trans['status']:
                status_item.setBackground(QColor(255, 200, 200))
            self.table_pending.setItem(row, 5, status_item)
        
        # Histórico de transações
        self.table_history.setRowCount(len(self.processador.historico_transacoes))
        for row, trans in enumerate(reversed(self.processador.historico_transacoes)):
            self.table_history.setItem(row, 0, QTableWidgetItem(trans['id']))
            self.table_history.setItem(row, 1, QTableWidgetItem(
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(trans['timestamp']))
            ))
            self.table_history.setItem(row, 2, QTableWidgetItem(trans['origem']))
            self.table_history.setItem(row, 3, QTableWidgetItem(trans['destino']))
            self.table_history.setItem(row, 4, QTableWidgetItem(f"{trans['valor']:.2f} {trans['moeda']}"))
            
            if 'valor_convertido' in trans:
                self.table_history.setItem(row, 5, QTableWidgetItem(
                    f"{trans['valor_convertido']:.5f} {trans['moeda_destino']}"
                ))
            else:
                self.table_history.setItem(row, 5, QTableWidgetItem("N/A"))
                
            self.table_history.setItem(row, 6, QTableWidgetItem(trans['moeda_destino']))
            
            status_item = QTableWidgetItem(trans['status'])
            if "Processado" in trans['status']:
                status_item.setBackground(QColor(200, 255, 200))
            elif "Erro" in trans['status']:
                status_item.setBackground(QColor(255, 200, 200))
            self.table_history.setItem(row, 7, status_item)
    
    def atualizar_reservas(self):
        # Reservas
        self.table_reserves.setRowCount(len(ParceirosBRICS_APEX.RESERVAS))
        for row, (moeda, valor) in enumerate(ParceirosBRICS_APEX.RESERVAS.items()):
            self.table_reserves.setItem(row, 0, QTableWidgetItem(moeda))
            self.table_reserves.setItem(row, 1, QTableWidgetItem(f"{valor:,.2f}"))
        
        # Taxas
        self.table_taxas.setRowCount(len(ParceirosBRICS_APEX.TAXAS_OFICIAIS))
        for row, ((de, para), taxa) in enumerate(ParceirosBRICS_APEX.TAXAS_OFICIAIS.items()):
            self.table_taxas.setItem(row, 0, QTableWidgetItem(de))
            self.table_taxas.setItem(row, 1, QTableWidgetItem(para))
            self.table_taxas.setItem(row, 2, QTableWidgetItem(f"{taxa:.5f}"))
    
    def atualizar_chaves(self):
        kyber_pub = self.processador.cripto.serializar_chave_publica(
            self.processador.cripto.kyber_pub_key
        )
        dilithium_pub = self.processador.cripto.serializar_chave_publica(
            self.processador.cripto.dilithium_pub_key
        )
        
        kyber_priv_hash = self.processador.cripto.hash_chave_privada(
            self.processador.cripto.kyber_priv_key
        )
        dilithium_priv_hash = self.processador.cripto.hash_chave_privada(
            self.processador.cripto.dilithium_priv_key
        )
        
        self.label_kyber_pub.setText(kyber_pub[:120] + "...")
        self.label_dilithium_pub.setText(dilithium_pub[:120] + "...")
        self.label_kyber_priv_hash.setText(kyber_priv_hash)
        self.label_dilithium_priv_hash.setText(dilithium_priv_hash)

# =============================================================================
# Execução do Aplicativo
# =============================================================================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Estilo global
    app.setStyle("Fusion")
    app.setFont(QFont("Arial", 10))
    
    window = BRICSPayApp()
    window.show()
    sys.exit(app.exec_())
