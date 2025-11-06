"""
Enterprise Network Packet Analyzer
Main Application Entry Point
"""

import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from ui.main_window import MainWindow

def main():
    """Initialize and run the application"""
    # PyQt6 handles High DPI automatically, no need to set attributes
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Apply dark futuristic theme
    app.setStyleSheet("""
        QMainWindow, QWidget {
            background-color: #0a0e27;
            color: #00ff88;
            font-family: 'Consolas', 'Monaco', monospace;
        }
        QTableWidget {
            background-color: #0f1535;
            alternate-background-color: #12183a;
            gridline-color: #1a2550;
            border: 2px solid #00ff88;
            border-radius: 5px;
        }
        QTableWidget::item:selected {
            background-color: #00ff8844;
        }
        QHeaderView::section {
            background-color: #1a2550;
            color: #00ff88;
            padding: 8px;
            border: 1px solid #00ff88;
            font-weight: bold;
        }
        QPushButton {
            background-color: #1a2550;
            color: #00ff88;
            border: 2px solid #00ff88;
            border-radius: 5px;
            padding: 8px 16px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #00ff8822;
            border-color: #00ffff;
        }
        QPushButton:pressed {
            background-color: #00ff8844;
        }
        QComboBox {
            background-color: #1a2550;
            color: #00ff88;
            border: 2px solid #00ff88;
            border-radius: 5px;
            padding: 5px;
        }
        QComboBox::drop-down {
            border: none;
        }
        QComboBox::down-arrow {
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid #00ff88;
        }
        QLineEdit, QTextEdit {
            background-color: #0f1535;
            color: #00ff88;
            border: 2px solid #00ff88;
            border-radius: 5px;
            padding: 5px;
        }
        QTabWidget::pane {
            border: 2px solid #00ff88;
            background-color: #0f1535;
        }
        QTabBar::tab {
            background-color: #1a2550;
            color: #00ff88;
            border: 2px solid #00ff88;
            border-bottom: none;
            padding: 8px 16px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #00ff8822;
        }
        QProgressBar {
            border: 2px solid #00ff88;
            border-radius: 5px;
            text-align: center;
            background-color: #0f1535;
        }
        QProgressBar::chunk {
            background-color: #00ff88;
        }
        QLabel {
            color: #00ff88;
        }
        QScrollBar:vertical {
            background-color: #0f1535;
            width: 12px;
            border: 1px solid #00ff88;
        }
        QScrollBar::handle:vertical {
            background-color: #00ff88;
            border-radius: 5px;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
    """)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == '__main__':
    main()