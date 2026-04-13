
from PIL import Image
from PIL.ExifTags import TAGS
import os

class MetadataExtractor:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.metadata = {}
        
    def extract(self) -> Dict:
        print(f"[*] Extrayendo metadatos de: {self.file_path}")
        
        file_ext = os.path.splitext(self.file_path)[1].lower()
        
        if file_ext in ['.jpg', '.jpeg', '.png', '.gif']:
            return self.extract_image_metadata()
        elif file_ext == '.pdf':
            return self.extract_pdf_metadata()
        else:
            return {'error': 'Tipo de archivo no soportado'}
    
    def extract_image_metadata(self) -> Dict:
        """Extrae metadatos EXIF de imágenes"""
        try:
            image = Image.open(self.file_path)
            exif_data = image._getexif()
            
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    self.metadata[tag] = str(value)
                    print(f"[+] {tag}: {value}")
            
            return self.metadata
            
        except Exception as e:
            return {'error': str(e)}
    
    def extract_pdf_metadata(self) -> Dict:
        """Extrae metadatos de PDF"""
        try:
            import PyPDF2
            
            with open(self.file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                info = pdf.metadata
                
                for key, value in info.items():
                    self.metadata[key] = value
                    print(f"[+] {key}: {value}")
            
            return self.metadata
            
        except ImportError:
            return {'error': 'PyPDF2 no instalado: pip install PyPDF2'}
        except Exception as e:
            return {'error': str(e)}

def extract(file_paths: List[str]) -> Dict:
    results = {}
    
    for file_path in file_paths:
        extractor = MetadataExtractor(file_path)
        results[file_path] = extractor.extract()
    
    return results
