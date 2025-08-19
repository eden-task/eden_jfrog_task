// Security middleware to mitigate body-parser CVE-2024-45590
// This middleware implements JFrog Advanced Security's recommended mitigations
// without updating the vulnerable body-parser version

const securityMiddleware = (req, res, next) => {
    // 1. Request size limiting to prevent DoS attacks
    const contentLength = parseInt(req.headers['content-length'] || '0');
    const MAX_SIZE = 1048576; // 1MB limit
    
    if (contentLength > MAX_SIZE) {
        return res.status(413).json({
            success: false,
            error: 'Request entity too large',
            maxSize: `${MAX_SIZE} bytes`
        });
    }
    
    // 2. Content-type validation to prevent malformed data attacks
    const contentType = req.headers['content-type'] || '';
    const allowedTypes = [
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data'
    ];
    
    if (contentType && !allowedTypes.some(type => contentType.includes(type))) {
        return res.status(415).json({
            success: false,
            error: 'Unsupported media type',
            allowedTypes
        });
    }
    
    // 3. Deep nesting protection to prevent stack overflow
    if (req.body && typeof req.body === 'object') {
        const depth = getObjectDepth(req.body);
        const MAX_DEPTH = 10;
        
        if (depth > MAX_DEPTH) {
            return res.status(400).json({
                success: false,
                error: 'Request object too deeply nested',
                maxDepth: MAX_DEPTH
            });
        }
        
        // 4. Input sanitization to prevent injection attacks
        sanitizeObject(req.body);
    }
    
    // 5. Rate limiting headers (informational)
    res.setHeader('X-RateLimit-Limit', '100');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    next();
};

// Helper function to calculate object depth
function getObjectDepth(obj, currentDepth = 0) {
    if (typeof obj !== 'object' || obj === null) {
        return currentDepth;
    }
    
    let maxDepth = currentDepth;
    
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            const depth = getObjectDepth(obj[key], currentDepth + 1);
            maxDepth = Math.max(maxDepth, depth);
        }
    }
    
    return maxDepth;
}

// Helper function to sanitize object values
function sanitizeObject(obj) {
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            if (typeof obj[key] === 'string') {
                // Remove potential XSS patterns
                obj[key] = obj[key]
                    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                    .replace(/javascript:/gi, '')
                    .replace(/on\w+\s*=/gi, '');
                
                // Limit string length to prevent memory exhaustion
                if (obj[key].length > 10000) {
                    obj[key] = obj[key].substring(0, 10000);
                }
            } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                sanitizeObject(obj[key]);
            }
        }
    }
}

module.exports = securityMiddleware;
