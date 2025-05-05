from __future__ import division
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
from collections import deque

class HybridDDoSDetector:
    def __init__(self):
        """
        Modelo híbrido que combina Random Forest y SVM para detección de DDoS.
        
        Estrategia:
        1. Random Forest como clasificador principal (mejor para datos desbalanceados)
        2. SVM como validador (mejor para márgenes claros)
        3. Votación ponderada entre ambos modelos
        """
        self.rf_model = None
        self.svm_model = None
        self.last_predictions = deque(maxlen=10)  # Para seguimiento de predicciones
        
        try:
            # Intentar cargar modelos pre-entrenados
            self.load_models()
            print("Modelos híbridos cargados exitosamente")
        except:
            print("Entrenando nuevos modelos...")
            self.train_hybrid_model()
    
    def load_models(self):
        """Carga los modelos desde archivos"""
        self.rf_model = joblib.load('rf_model.pkl')
        self.svm_model = joblib.load('svm_model.pkl')
    
    def save_models(self):
        """Guarda los modelos entrenados"""
        joblib.dump(self.rf_model, 'rf_model.pkl')
        joblib.dump(self.svm_model, 'svm_model.pkl')
    
    def train_hybrid_model(self):
        """Entrena ambos modelos con los datos de result.csv"""
        # Cargar y preparar datos
        data = np.loadtxt(open('result.csv', 'rb'), delimiter=',', dtype='str')
        X = data[:, 0:5].astype(float)
        y = data[:, 5]
        
        # Dividir datos
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42
        )
        
        # Entrenar Random Forest
        self.rf_model = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_split=3,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        self.rf_model.fit(X_train, y_train)
        
        # Entrenar SVM con kernel RBF
        self.svm_model = svm.SVC(
            kernel='rbf',
            C=1.0,
            gamma='scale',
            probability=True,
            class_weight='balanced'
        )
        self.svm_model.fit(X_train, y_train)
        
        # Evaluar modelos
        print("\nEvaluación Random Forest:")
        y_pred_rf = self.rf_model.predict(X_test)
        print(classification_report(y_test, y_pred_rf))
        
        print("\nEvaluación SVM:")
        y_pred_svm = self.svm_model.predict(X_test)
        print(classification_report(y_test, y_pred_svm))
        
        # Guardar modelos
        self.save_models()
    
    def hybrid_predict(self, features):
        """
        Predicción híbrida que combina ambos modelos.
        
        Estrategia:
        1. Obtener probabilidades de ambos modelos
        2. Si ambos están muy seguros (prob > 0.8), usar voto mayoritario
        3. Si uno está más seguro que el otro, usar ese
        4. Si ambos están inseguros, usar Random Forest (mejor con datos desbalanceados)
        """
        try:
            # Convertir a array numpy
            features = np.array(features).reshape(1, -1).astype(float)
            
            # Obtener probabilidades
            rf_proba = self.rf_model.predict_proba(features)[0]
            svm_proba = self.svm_model.predict_proba(features)[0]
            
            # Obtener clases y confianzas
            rf_class = self.rf_model.classes_[np.argmax(rf_proba)]
            rf_confidence = np.max(rf_proba)
            
            svm_class = self.svm_model.classes_[np.argmax(svm_proba)]
            svm_confidence = np.max(svm_proba)
            
            # Lógica de decisión híbrida
            if rf_confidence > 0.8 and svm_confidence > 0.8:
                # Ambos seguros: voto mayoritario
                final_pred = rf_class if rf_class == svm_class else '1'  # En caso de empate, marcar como ataque
            elif rf_confidence > svm_confidence + 0.1:
                # RF más seguro
                final_pred = rf_class
            elif svm_confidence > rf_confidence + 0.1:
                # SVM más seguro
                final_pred = svm_class
            else:
                # Ambos inseguros o similares: usar RF
                final_pred = rf_class
            
            # Guardar predicción para seguimiento
            self.last_predictions.append(final_pred)
            
            # Si hay 5 de las últimas 10 predicciones como ataque, marcar como ataque
            if list(self.last_predictions).count('1') >= 5:
                return ['1']
            
            return [final_pred]
            
        except Exception as e:
            print(f"Error en predicción híbrida: {str(e)}")
            return ['0']  # Por defecto asume tráfico normal

class MachineLearningAlgo:
    """
    Wrapper para mantener compatibilidad con el código existente
    mientras usamos el nuevo detector híbrido
    """
    def __init__(self):
        self.detector = HybridDDoSDetector()
    
    def classify(self, data):
        return self.detector.hybrid_predict(data)