# Password Pattern Analysis Tool

A comprehensive password analysis tool designed to extract patterns from cracked passwords and generate optimized wordlists for password security research and analysis.

**Current Version: v3.0.0**

## Features

### Core Analysis
- **Root Word Extraction** - Extracts base words by removing common transforms (numbers, symbols, substitutions)
- **Case Pattern Analysis** - Identifies capitalization patterns (UPPER, lower, Title, MiXeD)
- **Year Pattern Detection** - Finds years from 1900-2029 in passwords
- **Date Pattern Analysis** - Extracts date patterns in various formats (DD/MM/YYYY, MM-DD-YYYY, etc.)
- **Number Pattern Extraction** - Finds numeric sequences with configurable minimum length filtering
- **Substitution Mapping** - Detects common character substitutions (a→@, e→3, i→1, o→0, etc.)
- **Keyboard Walk Detection** - Identifies keyboard patterns (qwerty, asdf, 123456, etc.)
- **N-gram Analysis** - Extracts 2-4 character sequences for pattern recognition
- **Markov Chain Analysis** - Builds character transition probabilities (5-10 character chains)
- **Adaptive Markov Chains** - Context-aware and position-specific chain analysis
- **Language Pattern Detection** - Identifies English, Spanish, German, French, Portuguese patterns
- **Temporal Pattern Analysis** - Detects seasonal, monthly, holiday, and day-of-week patterns
- **Compound Word Analysis** - Analyzes multi-word combinations with various separators
- **Domain Pattern Recognition** - Identifies corporate, gaming, social media, personal contexts
- **Reversed Pattern Analysis** - Stores reversed passwords and keywords for analysis

### Security Analysis Integration  
- **Pattern Recognition** - Identifies common password construction patterns
- **Frequency-based Filtering** - Only includes patterns above specified threshold
- **Multi-format Output** - Generates various wordlist formats for analysis

## Installation

### Prerequisites
- Go 1.21 or higher

### Build
```bash
go build -o phurtimAnalyzer main.go
```

## Usage

### Basic Syntax
```bash
./phurtimAnalyzer <password_file> <output_dir> <min_frequency> <min_num_length> [max_results]
```

### Parameters
- `password_file`: Path to file containing cracked passwords (one per line)
- `output_dir`: Directory where wordlists and rules will be saved
- `min_frequency`: Minimum occurrence threshold (patterns below this are filtered out)
- `min_num_length`: Minimum length for number patterns (e.g., 2 to skip single digits)
- `max_results`: Maximum results per category (default: 1000)

### Examples

**Basic Analysis:**
```bash
./phurtimAnalyzer passwords.txt ./output 5 2 500
```

**High-frequency patterns only:**
```bash
./phurtimAnalyzer passwords.txt ./output 25 3 100
```

**Large dataset analysis:**
```bash
./phurtimAnalyzer megalist.txt ./output 10 2 20000
```

## Output Files

The tool generates multiple files optimized for password pattern analysis:

### Main Directory Files
- `rootwords.txt` - Clean base words without transforms
- `hybrid_words.txt` - Word components for hybrid attacks
- `years.txt` - Extracted years for appending/prepending
- `numbers.txt` - Numeric sequences (length filtered by min_num_length)
- `date_patterns.txt` - Date patterns in various formats
- `compound_words.txt` - Multi-word combinations
- `compound_words_plus.txt` - Words with + separator
- `compound_words_minus.txt` - Words with - separator
- `compound_words_underscore.txt` - Words with _ separator
- `compound_words_asterisk.txt` - Words with * separator
- `compound_words_dot.txt` - Words with . separator
- `compound_words_colon.txt` - Words with : separator
- `reversed_keywords.txt` - Reversed word patterns
- `reversed_passwords.txt` - Complete reversed password list
- `reversed_compound_words.txt` - Reversed compound word patterns

### Subdirectories
- `separators/separators.txt` - Common word separators analysis
- `ngrams/` - N-gram files (2grams.txt, 3grams.txt, 4grams.txt)
- `markov/` - Markov chain files (5-10 character chains, adaptive chains)
- `smallLists/` - Curated top 100/1000 files for focused attacks
  - `top_100_compound_words.txt`
  - `top_100_numbers.txt`
  - `top_100_root_and_hybrid.txt`
  - `top_1000_root_and_hybrid.txt`
  - `root_and_hybrid_with_space.txt`
  - `root_and_hybrid_with_dash.txt`

## Analysis Applications

### Security Research
```bash
# Analyze password patterns for research
cat rootwords.txt | head -20  # View most common base words
cat years.txt | sort | uniq -c | sort -nr  # Analyze year usage patterns
```

### Password Policy Development
```bash
# Examine common patterns to improve policies
cat compound_words.txt | head -50  # Common multi-word patterns
cat numbers.txt | head -20  # Most frequent number sequences
```

### Pattern Frequency Analysis
```bash
# Statistical analysis of password construction
wc -l *.txt  # Count patterns in each category
cat reversed_keywords.txt | head -10  # Check reverse patterns
```

## Analysis Report

The tool provides a comprehensive analysis report showing:

```
Password Analysis Report
========================
Total passwords analyzed: 55
Minimum frequency threshold: 2

Analysis Categories:
- Root words: 21 unique
- Case patterns: 16 unique
- Year patterns: 5 unique
- Substitution patterns: 6 unique
- Keyboard walks: 8 unique
- N-grams: 388 unique
- Hybrid parts: 20 unique
- Length groups: 5 unique

Top 10 Root Words:
 1. password        (11)
 2. admin           (3)
 3. welcome         (3)
 4. football        (3)
 5. letmein         (3)
...
```

## Advanced Usage

### Optimizing for Target Organizations
```bash
# High-frequency patterns for corporate environments
./phurtimAnalyzer corporate_passwords.txt ./corporate_output 10 3 200

# Analyze corporate-specific patterns
cat corporate_output/rootwords.txt | head -20
cat corporate_output/compound_words.txt | grep -i company
```

### Gaming Environment Analysis
```bash
# Lower threshold for gaming passwords (more diverse)
./phurtimAnalyzer gaming_passwords.txt ./gaming_output 3 2 1000

# Examine gaming-specific patterns
cat gaming_output/compound_words.txt | grep -i game
cat gaming_output/numbers.txt | head -20
```

### Focused Number Pattern Analysis  
```bash
# Skip single digits, focus on 3+ digit sequences
./phurtimAnalyzer passwords.txt ./output 5 3 500

# Include single digits for comprehensive analysis
./phurtimAnalyzer passwords.txt ./output 5 1 500
```

## Pattern Detection Details

### Root Word Extraction
- Removes trailing digits (password123 → password)
- Removes leading/trailing symbols (!password! → password)
- Reverses common substitutions (p@ssw0rd → password)
- Extracts longest alphabetic sequences

### Substitution Detection
Common substitutions detected:
- a → @
- e → 3
- i → 1
- o → 0
- s → $
- t → 7
- l → 1
- g → 9
- b → 6

### Keyboard Walk Detection
Patterns detected:
- QWERTY rows: qwerty, asdf, zxcv
- Number sequences: 123, 456, 789
- Diagonal patterns: qaz, wsx, edc
- Common walks: qwe, asd, zxc

### Year Pattern Detection
- Detects years from 1900-2029
- Accounts for both 19XX and 20XX formats
- Useful for age-based password patterns

### Date Pattern Detection
- Multiple formats: DD/MM/YYYY, MM/DD/YYYY, DD-MM-YYYY, MM-DD-YYYY
- Detects YYYY/MM/DD ISO format
- Handles both / and - separators
- Useful for birth dates and memorable dates

### Number Pattern Filtering
- Configurable minimum length (min_num_length parameter)
- Reduces noise from single digits when set to 2+
- Focuses on meaningful numeric sequences
- Improves wordlist quality for targeted attacks

### Advanced Markov Chain Analysis
- **5-10 character chains**: Multi-length analysis for different password complexities
- **Adaptive chains**: Variable-length context-aware analysis
- **Position-specific chains**: Location-aware pattern recognition
- **Context-aware chains**: Semantic context understanding

### Language-Specific Patterns
- **English**: Standard English words and patterns
- **Spanish**: Common Spanish password patterns
- **German**: German language constructions  
- **French**: French linguistic patterns
- **Portuguese**: Portuguese password conventions

### Temporal and Seasonal Analysis
- **Seasons**: spring, summer, autumn/fall, winter
- **Months**: Full names and abbreviations
- **Holidays**: christmas, halloween, easter, etc.
- **Days**: Weekday names and abbreviations

## Pattern Analysis Details

### Statistical Analysis
The tool provides comprehensive statistics on:
- Pattern frequency distribution
- Character usage patterns
- Structural composition analysis
- Temporal and contextual patterns

### Research Applications
- **Password strength assessment** - Identify weak patterns
- **Policy effectiveness** - Evaluate current password requirements
- **User behavior analysis** - Understand password creation habits
- **Security awareness** - Demonstrate common vulnerabilities

## Performance Tips

### Input File Optimization
- Remove duplicates before analysis to improve performance
- Sort by frequency for better pattern detection
- Use clean, validated password lists

### Threshold Selection
- **High security environments**: Use min_frequency 20-50
- **General analysis**: Use min_frequency 5-10
- **Comprehensive analysis**: Use min_frequency 2-3

### Memory Considerations
- Large password lists (>1M passwords) may require significant RAM
- Consider splitting very large files for processing
- Monitor system resources during analysis

## Output File Sizes

Typical output sizes for different input sizes:

| Input Size | Root Words | Rules | Masks | Total Output |
|------------|------------|-------|-------|-------------|
| 10K passwords | 500-1000 | 50-100 | 20-50 | 1-5 MB |
| 100K passwords | 2000-5000 | 100-200 | 50-100 | 10-25 MB |
| 1M passwords | 10000-20000 | 200-500 | 100-200 | 50-100 MB |

## Security Considerations

### Defensive Use Only
This tool is designed for:
- **Security research** - Understanding password patterns
- **Penetration testing** - Authorized security assessments
- **Password policy improvement** - Organizational security enhancement
- **Academic research** - Password security studies

### Ethical Guidelines
- Only analyze passwords obtained through authorized means
- Respect privacy and confidentiality requirements
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

## Troubleshooting

### Common Issues

**Memory errors with large files:**
```bash
# Split large files before processing
split -l 100000 large_passwords.txt split_
./phurtimAnalyzer split_aa ./output1 5 2 1000
./phurtimAnalyzer split_ab ./output2 5 2 1000
```

**Empty output files:**
```bash
# Check minimum frequency threshold
./phurtimAnalyzer passwords.txt ./output 1 1 1000  # Lower thresholds
```

**Too many single digit numbers:**
```bash
# Increase min_num_length to filter out noise
./phurtimAnalyzer passwords.txt ./output 5 3 1000  # Skip 1-2 digit numbers
```

### Debug Mode
For troubleshooting, you can examine intermediate results:
```bash
# Check if patterns are being detected
./phurtimAnalyzer passwords.txt ./debug_output 1 1 10
ls -la debug_output/
```

## Contributing

This tool is designed for security professionals and researchers. When contributing:

1. Focus on defensive security applications
2. Maintain ethical usage guidelines
3. Optimize for performance with large datasets
4. Follow Go best practices and conventions

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for compliance with applicable laws and regulations.

## Version History

- **v1.0** - Initial release with basic pattern analysis
- **v2.0** - Added hashcat integration and advanced analysis
- **v2.1** - Bug fixes and output formatting improvements
- **v2.2** - Enhanced rule generation and mask creation
- **v2.3** - Added date pattern analysis and number length filtering
- **v2.4** - Advanced Markov chains and language pattern detection
- **v2.5** - Compound words, temporal patterns, and domain-specific analysis
- **v2.6** - Reversed pattern analysis and adaptive Markov chains
- **v2.7** - Directory structure improvements and curated small lists
- **v3.0.0** - Major release with comprehensive date analysis, adaptive Markov chains, complete export function integration, and enhanced reversed pattern analysis

## Support

For issues, questions, or contributions:
- Review the troubleshooting section
- Check existing GitHub issues
- Submit detailed bug reports with sample data (anonymized)

---

**Remember**: This tool is for authorized security testing and research only. Always ensure you have proper authorization before analyzing password data.