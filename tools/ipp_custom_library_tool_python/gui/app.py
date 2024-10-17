"""
Copyright (C) 2018 Intel Corporation

SPDX-License-Identifier: MIT
"""

import json
import os

from PyQt5.QtCore import QEvent, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QDesktopWidget, QFileDialog, QGridLayout, QMainWindow, QMessageBox, QWidget

from gui.controller import Controller
from gui.custom_functions_panel import CustomFunctionsPanel
from gui.selection_panel import SelectionPanel
from gui.settings_panel import SettingsPanel
from tool import utils


class MainAppWindow(QMainWindow):
    def __init__(self):
        super(MainAppWindow, self).__init__()
        self.setWindowIcon(QIcon("icon.ico"))
        self.setWindowTitle("Intel(R) Integrated Performance Primitives Custom Library Tool")

        project_menu = self.menuBar()

        open_action = project_menu.addAction("Open project")
        save_action = project_menu.addAction("Save project")
        save_as_action = project_menu.addAction("Save project as...")

        self.settings_panel = SettingsPanel()
        self.selection_panel = SelectionPanel(self.settings_panel)
        self.custom_functions_panel = CustomFunctionsPanel(self.settings_panel)

        self.controller = Controller(self, self.settings_panel, self.selection_panel, self.custom_functions_panel)

        widget = QWidget()
        self.setCentralWidget(widget)

        layout = QGridLayout()
        layout.addWidget(self.settings_panel, 0, 0, 1, 3)
        layout.addWidget(self.selection_panel, 1, 0)
        layout.addWidget(self.controller, 1, 1, Qt.AlignCenter)
        layout.addWidget(self.custom_functions_panel, 1, 2)
        widget.setLayout(layout)

        open_action.triggered.connect(self.on_open)
        save_action.triggered.connect(self.on_save)
        save_as_action.triggered.connect(self.on_save_as)

        self.project = ""
        self.show()

    def on_open(self):
        while True:
            extension = f"CLT project (*{utils.PROJECT_EXTENSION})"
            chosen_path = QFileDialog.getOpenFileName(
                self, "Open project", "", extension, options=QFileDialog.DontResolveSymlinks
            )[0]
            if not chosen_path:
                return
            elif os.path.islink(chosen_path):
                QMessageBox.information(self, "ERROR!", "Please, select not a symlink")
                continue
            else:
                self.project = chosen_path
                break

        with open(self.project, "r") as project_file:
            configs = json.load(project_file)
            self.controller.set_configs(configs)

    def on_save(self):
        return self.on_save_as(self.project)

    def on_save_as(self, project):
        self.controller.get_selected_configs()

        if not project:
            extension = f"CLT project (*{utils.PROJECT_EXTENSION})"
            project = QFileDialog.getSaveFileName(self, "Save project as...", "", extension)[0]
            if not project:
                return
            else:
                self.project = project

        if utils.CONFIGS[utils.PACKAGE]:
            utils.CONFIGS[utils.PACKAGE] = utils.CONFIGS[utils.PACKAGE].root

        with open(project, "w") as project_file:
            json.dump(utils.CONFIGS, project_file)

    def event(self, e):
        if e.type() == QEvent.Show:
            qt_rectangle = self.frameGeometry()
            center_point = QDesktopWidget().availableGeometry().center()
            qt_rectangle.moveCenter(center_point)
            self.move(qt_rectangle.topLeft())

        return super().event(e)
