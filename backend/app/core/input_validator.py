"""Input Validator - Validates file types and sizes"""
from app.config import config
from app.utils.logger import logger

class InputValidator:
    """Validates uploaded files"""
    
    @staticmethod
    def validate_file(filename: str, file_size: int) -> tuple[bool, str]:
        """
        Validate file name and size
        
        Args:
            filename: Name of the file
            file_size: Size of file in bytes
            
        Returns:
            (is_valid, error_message)
        """
        # Check file extension
        ext = filename.split('.')[-1].lower()
        if ext not in config.ALLOWED_EXTENSIONS:
            error_msg = f"Unsupported file type: .{ext}. Allowed: {', '.join(config.ALLOWED_EXTENSIONS)}"
            logger.error(error_msg)
            return False, error_msg
        
        # Check file size
        if file_size > config.MAX_FILE_SIZE_BYTES:
            error_msg = f"File too large: {file_size / (1024*1024):.2f}MB. Max: {config.MAX_FILE_SIZE_MB}MB"
            logger.error(error_msg)
            return False, error_msg
        
        logger.info(f"File validation passed: {filename} ({file_size / 1024:.2f}KB)")
        return True, ""
    
    @staticmethod
    def validate_input_type(input_type: str) -> tuple[bool, str]:
        """
        Validate input type parameter
        
        Args:
            input_type: Type of input (text, file, log, etc)
            
        Returns:
            (is_valid, error_message)
        """
        valid_types = ["text", "file", "log", "sql", "chat"]
        if input_type not in valid_types:
            error_msg = f"Invalid input_type: {input_type}. Valid: {valid_types}"
            logger.error(error_msg)
            return False, error_msg
        
        return True, ""
