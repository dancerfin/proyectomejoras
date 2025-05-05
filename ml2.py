from sklearn.ensemble import RandomForestClassifier
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.utils import resample
import numpy as np
import joblib
from collections import deque
import pandas as pd

class HybridDDoSDetector:
    def __init__(self):
        self.rf_model = None
        self.svm_model = None
        self.last_predictions = deque(maxlen=15)  # Aumentar ventana
        self.load_or_train()

    def load_or_train(self):
        try:
            self.rf_model = joblib.load('rf_model.pkl')
            self.svm_model = joblib.load('svm_model.pkl')
            print("Modelos cargados exitosamente")
            
            # Verificar calidad de modelos cargados
            self.validate_models()
        except:
            print("Entrenando nuevos modelos...")
            self.train_hybrid_model()

    def validate_models(self):
        """Valida los modelos con datos de prueba"""
        data = pd.read_csv('result.csv')
        X = data.iloc[:, :-1].values
        y = data.iloc[:, -1].values
        
        # Balancear datos
        X_resampled, y_resampled = resample(X[y == '1'],
                                           y[y == '1'],
                                           n_samples=len(X[y == '0']),
                                           random_state=42)
        X_balanced = np.vstack((X[y == '0'], X_resampled))
        y_balanced = np.hstack((y[y == '0'], y_resampled))
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_balanced, y_balanced, test_size=0.3, random_state=42)
        
        print("\nValidación Random Forest:")
        y_pred = self.rf_model.predict(X_test)
        print(classification_report(y_test, y_pred))
        
        print("\nValidación SVM:")
        y_pred = self.svm_model.predict(X_test)
        print(classification_report(y_test, y_pred))

    def train_hybrid_model(self):
        """Entrena con datos balanceados y aumentados"""
        data = pd.read_csv('result.csv')
        X = data.iloc[:, :-1].values
        y = data.iloc[:, -1].values
        
        # Balanceo y aumento de datos
        X_resampled, y_resampled = resample(X[y == '1'],
                                           y[y == '1'],
                                           n_samples=2*len(X[y == '0']),
                                           random_state=42)
        X_balanced = np.vstack((X[y == '0'], X_resampled))
        y_balanced = np.hstack((y[y == '0'], y_resampled))
        
        # Entrenamiento
        X_train, X_test, y_train, y_test = train_test_split(
            X_balanced, y_balanced, test_size=0.3, random_state=42)
        
        # Random Forest con mejores parámetros
        self.rf_model = RandomForestClassifier(
            n_estimators=200,  # Aumentar árboles
            max_depth=15,
            min_samples_split=2,
            class_weight='balanced_subsample',
            n_jobs=-1
        )
        self.rf_model.fit(X_train, y_train)
        
        # SVM con kernel RBF ajustado
        self.svm_model = svm.SVC(
            kernel='rbf',
            C=2.0,  # Mayor penalización
            gamma='scale',
            probability=True,
            class_weight='balanced'
        )
        self.svm_model.fit(X_train, y_train)
        
        # Evaluación
        print("\nEvaluación Random Forest:")
        y_pred = self.rf_model.predict(X_test)
        print(classification_report(y_test, y_pred))
        
        print("\nEvaluación SVM:")
        y_pred = self.svm_model.predict(X_test)
        print(classification_report(y_test, y_pred))
        
        # Guardar modelos
        joblib.dump(self.rf_model, 'rf_model.pkl')
        joblib.dump(self.svm_model, 'svm_model.pkl')

    def hybrid_predict(self, features):
        """Predicción con umbrales adaptativos"""
        features = np.array(features).reshape(1, -1).astype(float)
        
        try:
            # Obtener probabilidades y confianzas
            rf_proba = self.rf_model.predict_proba(features)[0]
            svm_proba = self.svm_model.predict_proba(features)[0]
            
            rf_class = self.rf_model.classes_[np.argmax(rf_proba)]
            rf_confidence = np.max(rf_proba)
            
            svm_class = self.svm_model.classes_[np.argmax(svm_proba)]
            svm_confidence = np.max(svm_proba)
            
            # Lógica de decisión mejorada
            if rf_confidence > 0.7 or svm_confidence > 0.7:  # Umbral más bajo
                if rf_class == '1' or svm_class == '1':
                    final_pred = '1'
                else:
                    final_pred = '0'
            else:
                final_pred = rf_class  # Por defecto RF
            
            # Sistema de votación con ventana temporal
            self.last_predictions.append(final_pred)
            attack_count = list(self.last_predictions).count('1')
            
            if attack_count >= 7:  # 7 de 15 predicciones son ataque
                return ['1']
            
            return [final_pred]
            
        except Exception as e:
            print(f"Error en predicción: {str(e)}")
            return ['0']