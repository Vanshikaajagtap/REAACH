from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
import os

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Load your CSV data
def load_dengue_data():
    try:
        # Load the CSV file
        df = pd.read_csv('ph_dengue_cases2016-2020.csv')
        print(f"Loaded CSV with {len(df)} rows and columns: {list(df.columns)}")
        return df
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return pd.DataFrame()

# Global variable to store the data
dengue_data = load_dengue_data()

@app.route('/api/dengue-data', methods=['GET'])
def get_dengue_data():
    try:
        if dengue_data.empty:
            return jsonify({
                'success': False,
                'error': 'CSV file not loaded or empty'
            })
        
        # Convert to list of dictionaries for JSON response
        data_records = dengue_data.to_dict('records')
        
        return jsonify({
            'success': True,
            'data': data_records[:100],  # First 100 records
            'total_records': len(dengue_data),
            'columns': list(dengue_data.columns)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/regions', methods=['GET'])
def get_regions():
    try:
        if dengue_data.empty:
            return jsonify({
                'success': True,
                'regions': ['All Regions']
            })
        
        # Get unique regions from the CSV
        regions = dengue_data['Region'].unique().tolist()
        
        return jsonify({
            'success': True,
            'regions': ['All Regions'] + regions
        })
    except Exception as e:
        return jsonify({
            'success': True,
            'regions': ['All Regions'],
            'error': str(e)
        })

@app.route('/api/data-by-region', methods=['POST'])
def get_data_by_region():
    try:
        data = request.json
        region = data.get('region', 'All Regions')
        
        if dengue_data.empty:
            return jsonify({'success': False, 'error': 'No data loaded'})
        
        if region == 'All Regions':
            filtered_data = dengue_data
        else:
            filtered_data = dengue_data[dengue_data['Region'] == region]
        
        return jsonify({
            'success': True,
            'data': filtered_data.to_dict('records'),
            'region': region
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/predict', methods=['POST'])
def predict_outbreak():
    try:
        data = request.json
        region = data.get('region', 'All Regions')
        
        # Simple prediction logic - you can replace with your ML model
        if dengue_data.empty:
            return jsonify({
                'success': False,
                'error': 'No data available for prediction'
            })
        
        # Filter data for the selected region
        if region != 'All Regions':
            region_data = dengue_data[dengue_data['Region'] == region]
        else:
            region_data = dengue_data
        
        # Simple average prediction (replace with your actual ML model)
        avg_cases = region_data['Dengue_Cases'].mean()
        
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
    app.run(debug=True, port=5000, host='0.0.0.0')