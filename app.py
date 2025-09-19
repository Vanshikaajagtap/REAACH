from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
import os

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Load CSV data
def load_csv_data():
    try:
        csv_path = 'ph_dengue_cases2016-2020.csv'
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            print(f"Successfully loaded CSV: {len(df)} rows, {len(df.columns)} columns")
            print(f"Columns: {list(df.columns)}")
            print(f"Regions found: {df['Region'].unique()[:5] if 'Region' in df.columns else 'No Region column'}")
            return df
        else:
            print(f" CSV file not found: {csv_path}")
            print(f"Current directory files: {os.listdir('.')}")
            return pd.DataFrame()
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return pd.DataFrame()

# Global variable with your data
dengue_data = load_csv_data()

# Test endpoint
@app.route('/test')
def test():
    return jsonify({"message": "Flask server is working!", "data_loaded": not dengue_data.empty})

# Get available regions from CSV
@app.route('/api/regions', methods=['GET'])
def get_regions():
    try:
        if dengue_data.empty:
            return jsonify({
                'success': True,
                'regions': ['All Regions'],
                'message': 'No data loaded'
            })
        
        if 'Region' in dengue_data.columns:
            regions = dengue_data['Region'].unique().tolist()
            return jsonify({
                'success': True,
                'regions': ['All Regions'] + regions
            })
        else:
            return jsonify({
                'success': True,
                'regions': ['All Regions'],
                'message': f'No Region column. Available columns: {list(dengue_data.columns)}'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

# Get dengue data from CSV
@app.route('/api/dengue-data', methods=['GET'])
def get_dengue_data():
    try:
        if dengue_data.empty:
            return jsonify({
                'success': False,
                'error': 'CSV file not loaded. Make sure ph_dengue_cases2016-2020.csv is in the same folder.'
            })
        
        # Return first 100 records
        sample_data = dengue_data.head(100).to_dict('records')
        
        return jsonify({
            'success': True,
            'data': sample_data,
            'total_records': len(dengue_data),
            'columns': list(dengue_data.columns)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

# Make predictions
@app.route('/api/predict', methods=['POST'])
def predict_outbreak():
    try:
        data = request.json
        region = data.get('region', 'All Regions')
        
        if dengue_data.empty:
            return jsonify({
                'success': False,
                'error': 'No data available for prediction'
            })
        
        # Simple prediction based on historical average
        if region != 'All Regions' and 'Region' in dengue_data.columns:
            region_data = dengue_data[dengue_data['Region'] == region]
            avg_cases = region_data['Dengue_Cases'].mean() if 'Dengue_Cases' in dengue_data.columns else 0
        else:
            avg_cases = dengue_data['Dengue_Cases'].mean() if 'Dengue_Cases' in dengue_data.columns else 0
        
        return jsonify({
            'success': True,
            'predictions': [
                {'period': 'Next Month', 'predicted_cases': round(avg_cases)},
                {'period': 'Next 3 Months', 'predicted_cases': round(avg_cases * 3)}
            ],
            'region': region
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    print("🚀 Starting Flask server on port 5001...")
    print("📊 Loading CSV data...")
    app.run(debug=True, port=5001, host='0.0.0.0')