package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

const VERSION = "v3.6.0"

type PasswordAnalysis struct {
	RootWords           map[string]int
	CasePatterns        map[string]int
	YearPatterns        map[string]int
	NumberPatterns      map[string]int
	DatePatterns        map[string]int
	Substitutions       map[string]int
	KeyboardWalks       map[string]int
	NGrams              map[int]map[string]int
	CharTransitions     map[string]map[string]int
	HybridParts         map[string]int
	LanguagePatterns    map[string]int
	TemporalPatterns    map[string]int
	CompoundWords       map[string]int
	WordSeparators      map[string]int
	DomainPatterns      map[string]int
	MarkovChains        map[int]map[string]map[string]int
	PositionalChains    map[int]map[string]map[string]int
	RootWordsOriginal   map[string]int
	HybridPartsOriginal map[string]int
	CompoundWordsOriginal map[string]int
	ReversedPasswords   map[string]int
	ReversedKeywords    map[string]int
	ReversedCompoundWords map[string]int
	AdaptiveChains      map[string]map[string]int
	PositionSpecificChains map[string]map[string]map[string]int
	ContextAwareChains  map[string]map[string]int
	TotalPasswords      int
	MinFreq             int
	MinNumLength        int
}

type AnalysisResult struct {
	Pattern string
	Count   int
}

type SubstitutionMap struct {
	From string
	To   string
}

var commonSubs = []SubstitutionMap{
	{"a", "@"}, {"e", "3"}, {"i", "1"}, {"o", "0"}, {"s", "$"}, {"t", "7"}, {"l", "1"}, {"g", "9"}, {"b", "6"},
}

// Pre-compiled regexes for hot-path functions
var (
	reTrailingDigits   = regexp.MustCompile(`\d+$`)
	reLeadingNonAlpha  = regexp.MustCompile(`^[^a-zA-Z]+`)
	reTrailingNonAlpha = regexp.MustCompile(`[^a-zA-Z]+$`)
	reAlphaWords       = regexp.MustCompile(`[a-zA-Z]+`)
	reYear             = regexp.MustCompile(`(19[0-9]{2}|20[0-2][0-9])`)
	reDigits           = regexp.MustCompile(`\d+`)
	reHexOnly          = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// Pre-compiled date pattern regexes (initialized in init())
var compiledDatePatterns []*regexp.Regexp

var datePatternStrings = []string{
	`(0[1-9]|1[0-2])[\/\-\.](0[1-9]|[12][0-9]|3[01])[\/\-\.](19|20)\d{2}`,
	`(0[1-9]|[12][0-9]|3[01])[\/\-\.](0[1-9]|1[0-2])[\/\-\.](19|20)\d{2}`,
	`(19|20)\d{2}[\/\-\.](0[1-9]|1[0-2])[\/\-\.](0[1-9]|[12][0-9]|3[01])`,
	`(19|20)\d{2}[\/\-\.](0[1-9]|[12][0-9]|3[01])[\/\-\.](0[1-9]|1[0-2])`,
	`([1-9]|1[0-2])[\/\-\.]([1-9]|[12][0-9]|3[01])[\/\-\.](19|20)\d{2}`,
	`([1-9]|[12][0-9]|3[01])[\/\-\.]([1-9]|1[0-2])[\/\-\.](19|20)\d{2}`,
	`(19|20)\d{2}[\/\-\.]([1-9]|1[0-2])[\/\-\.]([1-9]|[12][0-9]|3[01])`,
	`(19|20)\d{2}[\/\-\.]([1-9]|[12][0-9]|3[01])[\/\-\.]([1-9]|1[0-2])`,
	`(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])(19|20)\d{2}`,
	`(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])(19|20)\d{2}`,
	`(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])`,
	`(19|20)\d{2}(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])`,
	`(0[1-9]|1[0-2])[\/\-\.](0[1-9]|[12][0-9]|3[01])[\/\-\.]\d{2}`,
	`(0[1-9]|[12][0-9]|3[01])[\/\-\.](0[1-9]|1[0-2])[\/\-\.]\d{2}`,
	`\d{2}[\/\-\.](0[1-9]|1[0-2])[\/\-\.](0[1-9]|[12][0-9]|3[01])`,
	`\d{2}[\/\-\.](0[1-9]|[12][0-9]|3[01])[\/\-\.](0[1-9]|1[0-2])`,
	`(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])\d{2}`,
	`(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])\d{2}`,
	`\d{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])`,
	`\d{2}(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])`,
}

func init() {
	compiledDatePatterns = make([]*regexp.Regexp, len(datePatternStrings))
	for i, pattern := range datePatternStrings {
		compiledDatePatterns[i] = regexp.MustCompile(pattern)
	}
}

var keyboardPatterns = []string{
	"qwerty", "asdf", "zxcv", "123", "456", "789", "qwe", "asd", "zxc", "wer", "sdf", "xcv",
	"qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm", "ik", "ol", "p;",
}

var commonWords = map[string]string{
	"password": "english", "admin": "english", "user": "english", "welcome": "english",
	"login": "english", "guest": "english", "master": "english", "root": "english",
	"secret": "english", "public": "english", "private": "english", "system": "english",
	"server": "english", "database": "english", "manager": "english", "service": "english",
	"test": "english", "temp": "english", "default": "english", "new": "english",
	"contrasena": "spanish", "clave": "spanish", "usuario": "spanish", "acceso": "spanish",
	"passwort": "german", "benutzer": "german", "zugang": "german", "geheim": "german",
	"motdepasse": "french", "utilisateur": "french", "acces": "french", "secretfr": "french",
	"senha": "portuguese", "usuariopt": "portuguese", "acessopt": "portuguese", "secreto": "portuguese",
}

var temporalPatterns = []string{
	"spring", "summer", "autumn", "fall", "winter",
	"january", "february", "march", "april", "may", "june",
	"july", "august", "september", "october", "november", "december",
	"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
	"christmas", "halloween", "easter", "thanksgiving", "newyear", "valentine",
	"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
	"mon", "tue", "wed", "thu", "fri", "sat", "sun",
}

var domainKeywords = map[string]string{
	"admin": "corporate", "manager": "corporate", "employee": "corporate", "staff": "corporate",
	"office": "corporate", "company": "corporate", "business": "corporate", "work": "corporate",
	"corp": "corporate", "enterprise": "corporate", "department": "corporate", "team": "corporate",
	"game": "gaming", "player": "gaming", "gamer": "gaming", "gaming": "gaming",
	"steam": "gaming", "xbox": "gaming", "playstation": "gaming", "nintendo": "gaming",
	"clan": "gaming", "guild": "gaming", "server": "gaming", "minecraft": "gaming",
	"social": "social", "facebook": "social", "twitter": "social", "instagram": "social",
	"email": "social", "mail": "social", "message": "social", "chat": "social",
	"home": "personal", "family": "personal", "personal": "personal", "private": "personal",
	"my": "personal", "me": "personal", "self": "personal", "own": "personal",
}

var wordSeparators = []string{
	".", "_", "-", "+", "=", "@", "#", "$", "%", "&", "*", "!", "?", "~", "|", "\\", "/", ":", ";", ",",
}

func NewPasswordAnalysis(minFreq int, minNumLength int) *PasswordAnalysis {
	return &PasswordAnalysis{
		RootWords:           make(map[string]int),
		CasePatterns:        make(map[string]int),
		YearPatterns:        make(map[string]int),
		NumberPatterns:      make(map[string]int),
		DatePatterns:        make(map[string]int),
		Substitutions:       make(map[string]int),
		KeyboardWalks:       make(map[string]int),
		NGrams:              make(map[int]map[string]int),
		CharTransitions:     make(map[string]map[string]int),
		HybridParts:         make(map[string]int),
		LanguagePatterns:    make(map[string]int),
		TemporalPatterns:    make(map[string]int),
		CompoundWords:       make(map[string]int),
		WordSeparators:      make(map[string]int),
		DomainPatterns:      make(map[string]int),
		MarkovChains:        make(map[int]map[string]map[string]int),
		PositionalChains:    make(map[int]map[string]map[string]int),
		RootWordsOriginal:   make(map[string]int),
		HybridPartsOriginal: make(map[string]int),
		CompoundWordsOriginal: make(map[string]int),
		ReversedPasswords:   make(map[string]int),
		ReversedKeywords:    make(map[string]int),
		ReversedCompoundWords: make(map[string]int),
		AdaptiveChains:      make(map[string]map[string]int),
		PositionSpecificChains: make(map[string]map[string]map[string]int),
		ContextAwareChains:  make(map[string]map[string]int),
		TotalPasswords:      0,
		MinFreq:             minFreq,
		MinNumLength:        minNumLength,
	}
}

// Merge combines counts from another PasswordAnalysis into this one.
// Used after parallel workers finish to consolidate results.
func (pa *PasswordAnalysis) Merge(other *PasswordAnalysis) {
	pa.TotalPasswords += other.TotalPasswords

	mergeMap := func(dst, src map[string]int) {
		for k, v := range src {
			dst[k] += v
		}
	}

	mergeMap(pa.RootWords, other.RootWords)
	mergeMap(pa.RootWordsOriginal, other.RootWordsOriginal)
	mergeMap(pa.CasePatterns, other.CasePatterns)
	mergeMap(pa.YearPatterns, other.YearPatterns)
	mergeMap(pa.NumberPatterns, other.NumberPatterns)
	mergeMap(pa.DatePatterns, other.DatePatterns)
	mergeMap(pa.Substitutions, other.Substitutions)
	mergeMap(pa.KeyboardWalks, other.KeyboardWalks)
	mergeMap(pa.HybridParts, other.HybridParts)
	mergeMap(pa.HybridPartsOriginal, other.HybridPartsOriginal)
	mergeMap(pa.LanguagePatterns, other.LanguagePatterns)
	mergeMap(pa.TemporalPatterns, other.TemporalPatterns)
	mergeMap(pa.CompoundWords, other.CompoundWords)
	mergeMap(pa.CompoundWordsOriginal, other.CompoundWordsOriginal)
	mergeMap(pa.WordSeparators, other.WordSeparators)
	mergeMap(pa.DomainPatterns, other.DomainPatterns)
	mergeMap(pa.ReversedPasswords, other.ReversedPasswords)
	mergeMap(pa.ReversedKeywords, other.ReversedKeywords)
	mergeMap(pa.ReversedCompoundWords, other.ReversedCompoundWords)

	// Merge NGrams: map[int]map[string]int
	for n, srcMap := range other.NGrams {
		if pa.NGrams[n] == nil {
			pa.NGrams[n] = make(map[string]int)
		}
		mergeMap(pa.NGrams[n], srcMap)
	}

	// Merge CharTransitions: map[string]map[string]int
	for from, srcMap := range other.CharTransitions {
		if pa.CharTransitions[from] == nil {
			pa.CharTransitions[from] = make(map[string]int)
		}
		mergeMap(pa.CharTransitions[from], srcMap)
	}

	// Merge MarkovChains: map[int]map[string]map[string]int
	for n, srcPrefixes := range other.MarkovChains {
		if pa.MarkovChains[n] == nil {
			pa.MarkovChains[n] = make(map[string]map[string]int)
		}
		for prefix, srcSuffixes := range srcPrefixes {
			if pa.MarkovChains[n][prefix] == nil {
				pa.MarkovChains[n][prefix] = make(map[string]int)
			}
			mergeMap(pa.MarkovChains[n][prefix], srcSuffixes)
		}
	}

	// Merge PositionalChains: map[int]map[string]map[string]int
	for n, srcPrefixes := range other.PositionalChains {
		if pa.PositionalChains[n] == nil {
			pa.PositionalChains[n] = make(map[string]map[string]int)
		}
		for prefix, srcSuffixes := range srcPrefixes {
			if pa.PositionalChains[n][prefix] == nil {
				pa.PositionalChains[n][prefix] = make(map[string]int)
			}
			mergeMap(pa.PositionalChains[n][prefix], srcSuffixes)
		}
	}

	// Merge AdaptiveChains: map[string]map[string]int
	for prefix, srcSuffixes := range other.AdaptiveChains {
		if pa.AdaptiveChains[prefix] == nil {
			pa.AdaptiveChains[prefix] = make(map[string]int)
		}
		mergeMap(pa.AdaptiveChains[prefix], srcSuffixes)
	}

	// Merge PositionSpecificChains: map[string]map[string]map[string]int
	for pos, srcPrefixes := range other.PositionSpecificChains {
		if pa.PositionSpecificChains[pos] == nil {
			pa.PositionSpecificChains[pos] = make(map[string]map[string]int)
		}
		for prefix, srcSuffixes := range srcPrefixes {
			if pa.PositionSpecificChains[pos][prefix] == nil {
				pa.PositionSpecificChains[pos][prefix] = make(map[string]int)
			}
			mergeMap(pa.PositionSpecificChains[pos][prefix], srcSuffixes)
		}
	}

	// Merge ContextAwareChains: map[string]map[string]int
	for key, srcSuffixes := range other.ContextAwareChains {
		if pa.ContextAwareChains[key] == nil {
			pa.ContextAwareChains[key] = make(map[string]int)
		}
		mergeMap(pa.ContextAwareChains[key], srcSuffixes)
	}
}

func (pa *PasswordAnalysis) AnalyzePassword(password string) {
	pa.TotalPasswords++
	
	// Skip hex-encoded passwords
	if isHexPattern(password) {
		return
	}
	
	pa.extractRootWord(password)
	pa.analyzeCasePattern(password)
	pa.extractYearPattern(password)
	pa.extractNumberPatterns(password)
	pa.extractDatePatterns(password)
	pa.analyzeSubstitutions(password)
	pa.detectKeyboardWalks(password)
	pa.extractNGrams(password)
	pa.buildCharTransitions(password)
	pa.extractHybridParts(password)
	pa.detectLanguagePatterns(password)
	pa.extractTemporalPatterns(password)
	pa.analyzeCompoundWords(password)
	pa.detectDomainPatterns(password)
	pa.buildEnhancedMarkovChains(password)
	pa.buildAdaptiveMarkovChains(password)
	// pa.storeReversedPassword(password)
	// pa.storeReversedKeywords(password)
	// pa.storeReversedCompoundWords(password)
}

func (pa *PasswordAnalysis) extractRootWord(password string) {
	cleaned := password

	cleaned = reTrailingDigits.ReplaceAllString(cleaned, "")
	cleaned = reLeadingNonAlpha.ReplaceAllString(cleaned, "")
	cleaned = reTrailingNonAlpha.ReplaceAllString(cleaned, "")

	for _, sub := range commonSubs {
		cleaned = strings.ReplaceAll(cleaned, sub.To, sub.From)
	}

	matches := reAlphaWords.FindAllString(cleaned, -1)
	
	for _, match := range matches {
		if len(match) >= 4 {
			pa.RootWords[strings.ToLower(match)]++
			pa.RootWordsOriginal[match]++
		}
	}
}

func (pa *PasswordAnalysis) analyzeCasePattern(password string) {
	pattern := ""
	for _, r := range password {
		if unicode.IsUpper(r) {
			pattern += "U"
		} else if unicode.IsLower(r) {
			pattern += "L"
		} else if unicode.IsDigit(r) {
			pattern += "D"
		} else {
			pattern += "S"
		}
	}
	pa.CasePatterns[pattern]++
}

func (pa *PasswordAnalysis) extractYearPattern(password string) {
	matches := reYear.FindAllString(password, -1)
	
	for _, match := range matches {
		pa.YearPatterns[match]++
	}
}

func (pa *PasswordAnalysis) extractNumberPatterns(password string) {
	matches := reDigits.FindAllString(password, -1)
	
	for _, match := range matches {
		if len(match) >= pa.MinNumLength {
			pa.NumberPatterns[match]++
		}
	}
}

func (pa *PasswordAnalysis) extractDatePatterns(password string) {
	for _, re := range compiledDatePatterns {
		matches := re.FindAllString(password, -1)
		for _, match := range matches {
			pa.DatePatterns[match]++
		}
	}
}

func (pa *PasswordAnalysis) analyzeSubstitutions(password string) {
	for _, sub := range commonSubs {
		if strings.Contains(password, sub.To) {
			pa.Substitutions[sub.From+"->"+sub.To]++
		}
	}
}

func (pa *PasswordAnalysis) detectKeyboardWalks(password string) {
	lower := strings.ToLower(password)
	for _, pattern := range keyboardPatterns {
		if strings.Contains(lower, pattern) {
			pa.KeyboardWalks[pattern]++
		}
	}
}

func (pa *PasswordAnalysis) extractNGrams(password string) {
	// Skipping n-grams 2-4; start at 5
	for n := 5; n <= 7; n++ {
		if pa.NGrams[n] == nil {
			pa.NGrams[n] = make(map[string]int)
		}
		for i := 0; i <= len(password)-n; i++ {
			ngram := password[i : i+n]
			if isValidNGram(ngram) {
				pa.NGrams[n][ngram]++
			}
		}
	}
}

func isValidNGram(ngram string) bool {
	if len(ngram) < 2 {
		return false
	}
	letterCount := 0
	for _, r := range ngram {
		if unicode.IsLetter(r) {
			letterCount++
		}
	}
	return letterCount >= len(ngram)/2
}

func (pa *PasswordAnalysis) buildCharTransitions(password string) {
	for i := 0; i < len(password)-1; i++ {
		from := string(password[i])
		to := string(password[i+1])
		
		if pa.CharTransitions[from] == nil {
			pa.CharTransitions[from] = make(map[string]int)
		}
		pa.CharTransitions[from][to]++
	}
}


func (pa *PasswordAnalysis) extractHybridParts(password string) {
	wordParts := reAlphaWords.FindAllString(password, -1)
	
	for _, part := range wordParts {
		if len(part) >= 4 {
			remaining := strings.ReplaceAll(password, part, "")
			if remaining != "" {
				pa.HybridParts[strings.ToLower(part)]++
				pa.HybridPartsOriginal[part]++
			}
		}
	}
}

func (pa *PasswordAnalysis) detectLanguagePatterns(password string) {
	lower := strings.ToLower(password)
	
	for word, language := range commonWords {
		if strings.Contains(lower, word) {
			pa.LanguagePatterns[language]++
		}
	}
}

func (pa *PasswordAnalysis) extractTemporalPatterns(password string) {
	lower := strings.ToLower(password)
	
	for _, pattern := range temporalPatterns {
		if strings.Contains(lower, pattern) {
			pa.TemporalPatterns[pattern]++
		}
	}
}

func (pa *PasswordAnalysis) analyzeCompoundWords(password string) {
	lower := strings.ToLower(password)

	for _, sep := range wordSeparators {
		if strings.Contains(password, sep) {
			pa.WordSeparators[sep]++

			parts := strings.Split(lower, sep)
			if len(parts) >= 2 {
				// Only store the compound word if it has multiple valid parts
				validParts := []string{}
				for _, part := range parts {
					if len(part) >= 3 {
						validParts = append(validParts, part)
					}
				}
				if len(validParts) >= 2 {
					compound := strings.Join(validParts, " ")
					pa.CompoundWords[compound]++
					pa.CompoundWordsOriginal[password]++
				}
			}
		}
	}

	wordParts := reAlphaWords.FindAllString(lower, -1)
	if len(wordParts) >= 2 {
		compound := strings.Join(wordParts, " ")
		pa.CompoundWords[compound]++
		pa.CompoundWordsOriginal[password]++
	}
}

func (pa *PasswordAnalysis) detectDomainPatterns(password string) {
	lower := strings.ToLower(password)
	
	for keyword, domain := range domainKeywords {
		if strings.Contains(lower, keyword) {
			pa.DomainPatterns[domain]++
		}
	}
}

func (pa *PasswordAnalysis) buildEnhancedMarkovChains(password string) {
	for n := 7; n <= 10; n++ {
		if pa.MarkovChains[n] == nil {
			pa.MarkovChains[n] = make(map[string]map[string]int)
		}

		for i := 0; i <= len(password)-n-1; i++ {
			prefix := password[i : i+n]
			suffix := string(password[i+n])

			if pa.MarkovChains[n][prefix] == nil {
				pa.MarkovChains[n][prefix] = make(map[string]int)
			}
			pa.MarkovChains[n][prefix][suffix]++
		}
	}
}

func (pa *PasswordAnalysis) storeReversedPassword(password string) {
	reversed := reverseString(password)
	pa.ReversedPasswords[reversed]++
}

func (pa *PasswordAnalysis) storeReversedKeywords(password string) {
	// Extract root words and reverse them
	cleaned := password

	cleaned = reTrailingDigits.ReplaceAllString(cleaned, "")
	cleaned = reLeadingNonAlpha.ReplaceAllString(cleaned, "")
	cleaned = reTrailingNonAlpha.ReplaceAllString(cleaned, "")

	for _, sub := range commonSubs {
		cleaned = strings.ReplaceAll(cleaned, sub.To, sub.From)
	}

	matches := reAlphaWords.FindAllString(cleaned, -1)
	
	for _, match := range matches {
		if len(match) >= 4 {
			reversedKeyword := reverseString(strings.ToLower(match))
			pa.ReversedKeywords[reversedKeyword]++
		}
	}
}

func (pa *PasswordAnalysis) storeReversedCompoundWords(password string) {
	lower := strings.ToLower(password)
	
	// Extract compound words from separators and reverse them
	for _, sep := range wordSeparators {
		if strings.Contains(password, sep) {
			parts := strings.Split(lower, sep)
			if len(parts) >= 2 {
				for _, part := range parts {
					if len(part) >= 3 {
						reversed := reverseString(part)
						pa.ReversedCompoundWords[reversed]++
					}
				}
			}
		}
	}
	
	// Extract compound words from concatenated words and reverse them
	wordParts := reAlphaWords.FindAllString(lower, -1)
	if len(wordParts) >= 2 {
		for _, part := range wordParts {
			if len(part) >= 3 {
				reversed := reverseString(part)
				pa.ReversedCompoundWords[reversed]++
			}
		}
	}
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// isHexPattern detects hex-encoded passwords and hex[*] patterns
func isHexPattern(password string) bool {
	// Check for hex[...] pattern
	if strings.HasPrefix(password, "hex[") && strings.HasSuffix(password, "]") {
		return true
	}
	
	// Check if password is entirely hexadecimal (likely hex-encoded)
	// Only consider strings longer than 16 characters to avoid false positives
	if len(password) > 16 {
		if reHexOnly.MatchString(password) {
			return true
		}
	}
	
	// Check for other common hex prefixes
	hexPrefixes := []string{"0x", "\\x", "$HEX[", "hex:", "HEX:"}
	for _, prefix := range hexPrefixes {
		if strings.HasPrefix(strings.ToLower(password), strings.ToLower(prefix)) {
			return true
		}
	}
	
	return false
}

func (pa *PasswordAnalysis) getOptimalChainLength(password string, pos int) int {
	passwordLen := len(password)
	
	if pos < 2 || pos > passwordLen-3 {
		return 2
	} else if pos < 4 || pos > passwordLen-5 {
		return 3
	} else {
		return min(5, passwordLen-pos-1)
	}
}

func (pa *PasswordAnalysis) getPositionType(pos, totalLen int) string {
	ratio := float64(pos) / float64(totalLen)
	
	if ratio < 0.25 {
		return "start"
	} else if ratio < 0.75 {
		return "middle"
	} else {
		return "end"
	}
}

func (pa *PasswordAnalysis) getContextType(password string, pos int) string {
	if pos >= len(password) {
		return "unknown"
	}
	
	char := password[pos]
	
	if unicode.IsLetter(rune(char)) {
		return "alpha"
	} else if unicode.IsDigit(rune(char)) {
		return "digit"
	} else {
		return "symbol"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (pa *PasswordAnalysis) buildAdaptiveMarkovChains(password string) {
	for i := 0; i < len(password); i++ {
		chainLength := pa.getOptimalChainLength(password, i)
		
		if i+chainLength < len(password) {
			prefix := password[i : i+chainLength]
			suffix := string(password[i+chainLength])
			
			if pa.AdaptiveChains[prefix] == nil {
				pa.AdaptiveChains[prefix] = make(map[string]int)
			}
			pa.AdaptiveChains[prefix][suffix]++
			
			positionType := pa.getPositionType(i, len(password))
			contextType := pa.getContextType(password, i)
			
			if pa.PositionSpecificChains[positionType] == nil {
				pa.PositionSpecificChains[positionType] = make(map[string]map[string]int)
			}
			if pa.PositionSpecificChains[positionType][prefix] == nil {
				pa.PositionSpecificChains[positionType][prefix] = make(map[string]int)
			}
			pa.PositionSpecificChains[positionType][prefix][suffix]++
			
			contextKey := fmt.Sprintf("%s_%s", prefix, contextType)
			if pa.ContextAwareChains[contextKey] == nil {
				pa.ContextAwareChains[contextKey] = make(map[string]int)
			}
			pa.ContextAwareChains[contextKey][suffix]++
		}
	}
}


func (pa *PasswordAnalysis) GetTopResults(data map[string]int, limit int) []AnalysisResult {
	var results []AnalysisResult
	
	for pattern, count := range data {
		if count >= pa.MinFreq {
			results = append(results, AnalysisResult{
				Pattern: pattern,
				Count:   count,
			})
		}
	}
	
	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})
	
	if len(results) > limit {
		results = results[:limit]
	}
	
	return results
}

func (pa *PasswordAnalysis) ExportWordlists(outputDir string, limit int) {
	os.MkdirAll(outputDir, 0755)
	// os.MkdirAll(outputDir+"/separators", 0755)
	// os.MkdirAll(outputDir+"/smallLists", 0755)
	os.MkdirAll(outputDir+"/ngrams", 0755)
	os.MkdirAll(outputDir+"/markov", 0755)
	
	pa.exportRootAndHybridWords(outputDir, limit)
	pa.exportRootAndHybridWordsOriginalContext(outputDir, limit)
	// pa.exportYears(outputDir, limit)
	pa.exportNumbers(outputDir, limit)
	pa.exportDatePatterns(outputDir, limit)
	pa.exportSeparateNGrams(outputDir, limit)
	pa.exportCompoundWords(outputDir, limit)
	pa.exportCompoundWordsOriginalContext(outputDir, limit)
	// pa.exportCompoundWordsWithSeparator(outputDir, limit, "+", "compound_words_plus.txt")
	// pa.exportCompoundWordsWithSeparator(outputDir, limit, "-", "compound_words_minus.txt")
	// pa.exportCompoundWordsWithSeparator(outputDir, limit, "_", "compound_words_underscore.txt")
	// pa.exportCompoundWordsWithSeparator(outputDir, limit, "*", "compound_words_asterisk.txt")
	// pa.exportCompoundWordsWithSeparator(outputDir, limit, ".", "compound_words_dot.txt")
	// pa.exportCompoundWordsWithSeparator(outputDir, limit, ":", "compound_words_colon.txt")
	// pa.exportWordSeparators(outputDir, limit)
	// pa.exportReversedPasswords(outputDir, limit)
	// pa.exportReversedKeywords(outputDir, limit)
	// pa.exportReversedCompoundWords(outputDir, limit)
	pa.exportMarkovChains(outputDir, limit)
	pa.exportAdaptiveMarkovChains(outputDir, limit)

	// Export top 100/1000 files to smallLists directory
	// pa.exportTop100CompoundWords(outputDir)
	// pa.exportTop100Numbers(outputDir)
	// pa.exportTop100RootAndHybrid(outputDir)
	// pa.exportTop1000RootAndHybrid(outputDir)
	// pa.exportRootAndHybridWithSpace(outputDir)
	// pa.exportTop10000RootAndHybridWithSpace(outputDir)
	// pa.exportTop20000RootAndHybridWithSpace(outputDir)
	// pa.exportTop1000CompoundWordsWithSpaces(outputDir)
	// pa.exportTop10000CompoundWordsWithSpaces(outputDir)
	// pa.exportTop20000CompoundWordsWithSpaces(outputDir)
	// pa.exportRootAndHybridWithDash(outputDir)
}




func (pa *PasswordAnalysis) exportYears(outputDir string, limit int) {
	years := pa.GetTopResults(pa.YearPatterns, limit)
	
	file, err := os.Create(outputDir + "/years.txt")
	if err != nil {
		log.Printf("Error creating years.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range years {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) exportNumbers(outputDir string, limit int) {
	numbers := pa.GetTopResults(pa.NumberPatterns, limit)
	
	file, err := os.Create(outputDir + "/numbers.txt")
	if err != nil {
		log.Printf("Error creating numbers.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range numbers {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) exportDatePatterns(outputDir string, limit int) {
	dates := pa.GetTopResults(pa.DatePatterns, limit)
	
	file, err := os.Create(outputDir + "/dates.txt")
	if err != nil {
		log.Printf("Error creating dates.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range dates {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) exportSeparateNGrams(outputDir string, limit int) {
	for n := 5; n <= 7; n++ {
		if ngramsMap, exists := pa.NGrams[n]; exists {
			ngrams := pa.GetTopResults(ngramsMap, limit)
			
			filename := fmt.Sprintf("%s/ngrams/%dgrams.txt", outputDir, n)
			file, err := os.Create(filename)
			if err != nil {
				log.Printf("Error creating %s: %v", filename, err)
				continue
			}
			defer file.Close()
			
			for i, result := range ngrams {
				if i > 0 {
					fmt.Fprintf(file, "\n")
				}
				fmt.Fprintf(file, "%s", result.Pattern)
			}
		}
	}
}



func (pa *PasswordAnalysis) exportCompoundWords(outputDir string, limit int) {
	compounds := pa.GetTopResults(pa.CompoundWords, limit)
	
	file, err := os.Create(outputDir + "/compound_words.txt")
	if err != nil {
		log.Printf("Error creating compound_words.txt: %v", err)
		return
	}
	defer file.Close()
	
	// Use a map to store unique entries and their frequencies
	uniqueEntries := make(map[string]int)
	
	for _, result := range compounds {
		pattern := result.Pattern
		
		// Only include multi-word entries (contains spaces and has at least 2 words)
		if strings.Contains(pattern, " ") {
			words := strings.Fields(pattern)
			if len(words) > 1 {
				// Generate only multi-word n-gram substrings (skip single words)
				for i := 0; i < len(words); i++ {
					for j := i + 2; j <= len(words); j++ { // Start from i+2 to ensure at least 2 words
						substring := strings.Join(words[i:j], " ")
						// Add to unique entries, combining frequencies
						uniqueEntries[substring] += result.Count
					}
				}
				// Also add the full compound word
				uniqueEntries[pattern] += result.Count
			}
		}
		// Skip single word entries entirely
	}
	
	// Convert map back to slice and sort by frequency
	var sortedEntries []AnalysisResult
	for pattern, count := range uniqueEntries {
		sortedEntries = append(sortedEntries, AnalysisResult{
			Pattern: pattern,
			Count:   count,
		})
	}
	
	// Sort by count (descending)
	sort.Slice(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].Count > sortedEntries[j].Count
	})
	
	// Apply limit after processing
	if len(sortedEntries) > limit {
		sortedEntries = sortedEntries[:limit]
	}
	
	// Write to file
	for i, result := range sortedEntries {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) exportCompoundWordsWithSeparator(outputDir string, limit int, separator string, filename string) {
	compounds := pa.GetTopResults(pa.CompoundWords, limit)
	
	file, err := os.Create(outputDir + "/" + filename)
	if err != nil {
		log.Printf("Error creating %s: %v", filename, err)
		return
	}
	defer file.Close()
	
	// Use a map to store unique entries and their frequencies
	uniqueEntries := make(map[string]int)
	
	for _, result := range compounds {
		pattern := result.Pattern
		
		// Only include multi-word entries (contains spaces and has at least 2 words)
		if strings.Contains(pattern, " ") {
			words := strings.Fields(pattern)
			if len(words) > 1 {
				// Generate only multi-word n-gram substrings (skip single words)
				for i := 0; i < len(words); i++ {
					for j := i + 2; j <= len(words); j++ { // Start from i+2 to ensure at least 2 words
						substring := strings.Join(words[i:j], separator)
						// Add to unique entries, combining frequencies
						uniqueEntries[substring] += result.Count
					}
				}
				// Also add the full compound word with separator
				uniqueEntries[strings.ReplaceAll(pattern, " ", separator)] += result.Count
			}
		}
		// Skip single word entries entirely
	}
	
	// Convert map back to slice and sort by frequency
	var sortedEntries []AnalysisResult
	for pattern, count := range uniqueEntries {
		sortedEntries = append(sortedEntries, AnalysisResult{
			Pattern: pattern,
			Count:   count,
		})
	}
	
	// Sort by count (descending)
	sort.Slice(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].Count > sortedEntries[j].Count
	})
	
	// Apply limit after processing
	if len(sortedEntries) > limit {
		sortedEntries = sortedEntries[:limit]
	}
	
	// Write to file
	for i, result := range sortedEntries {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) exportWordSeparators(outputDir string, limit int) {
	separators := pa.GetTopResults(pa.WordSeparators, limit)
	
	file, err := os.Create(outputDir + "/separators/separators.txt")
	if err != nil {
		log.Printf("Error creating separators/separators.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range separators {
		// Only include symbols (non-alphanumeric characters)
		if len(result.Pattern) == 1 && !unicode.IsLetter(rune(result.Pattern[0])) && !unicode.IsDigit(rune(result.Pattern[0])) {
			if i > 0 {
				fmt.Fprintf(file, "\n")
			}
			fmt.Fprintf(file, "%s", result.Pattern)
		}
	}
}


func (pa *PasswordAnalysis) exportReversedPasswords(outputDir string, limit int) {
	// Create a slice of all reversed passwords (bypassing frequency filter)
	var reversed []AnalysisResult
	for password, count := range pa.ReversedPasswords {
		reversed = append(reversed, AnalysisResult{
			Pattern: password,
			Count:   count,
		})
	}
	
	// Sort by count (descending)
	sort.Slice(reversed, func(i, j int) bool {
		return reversed[i].Count > reversed[j].Count
	})
	
	// Limit results
	if len(reversed) > limit {
		reversed = reversed[:limit]
	}
	
	file, err := os.Create(outputDir + "/reversed_passwords.txt")
	if err != nil {
		log.Printf("Error creating reversed_passwords.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range reversed {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) exportReversedKeywords(outputDir string, limit int) {
	reversedKeywords := pa.GetTopResults(pa.ReversedKeywords, limit)
	
	file, err := os.Create(outputDir + "/reversed_keywords.txt")
	if err != nil {
		log.Printf("Error creating reversed_keywords.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range reversedKeywords {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) exportReversedCompoundWords(outputDir string, limit int) {
	reversedCompounds := pa.GetTopResults(pa.ReversedCompoundWords, limit)
	
	file, err := os.Create(outputDir + "/reversed_compound_words.txt")
	if err != nil {
		log.Printf("Error creating reversed_compound_words.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range reversedCompounds {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) exportMarkovChains(outputDir string, limit int) {
	for n := 7; n <= 10; n++ {
		if chains, exists := pa.MarkovChains[n]; exists {
			filename := fmt.Sprintf("%s/markov/markov_chains_%d.txt", outputDir, n)
			file, err := os.Create(filename)
			if err != nil {
				log.Printf("Error creating %s: %v", filename, err)
				continue
			}
			defer file.Close()
			
			count := 0
			for prefix, suffixes := range chains {
				if count >= limit {
					break
				}
				for suffix, freq := range suffixes {
					if freq >= pa.MinFreq {
						fmt.Fprintf(file, "%s%s\n", prefix, suffix)
						count++
						if count >= limit {
							break
						}
					}
				}
			}
		}
	}
}

// Export combined root and hybrid words as unique wordlist
func (pa *PasswordAnalysis) exportRootAndHybridWords(outputDir string, limit int) {
	// Combine root words and hybrid parts into one unique map
	combinedWords := make(map[string]int)
	
	// Add root words
	for word, count := range pa.RootWords {
		combinedWords[word] = count
	}
	
	// Add hybrid parts, combining counts if word exists in both
	for word, count := range pa.HybridParts {
		if existingCount, exists := combinedWords[word]; exists {
			combinedWords[word] = existingCount + count
		} else {
			combinedWords[word] = count
		}
	}
	
	// Get top results using the combined map
	results := pa.GetTopResults(combinedWords, limit)
	
	file, err := os.Create(outputDir + "/rootAndHybrid_words.txt")
	if err != nil {
		log.Printf("Error creating rootAndHybrid_words.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range results {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

// Export combined root and hybrid words with original casing
func (pa *PasswordAnalysis) exportRootAndHybridWordsOriginalContext(outputDir string, limit int) {
	combinedWords := make(map[string]int)

	for word, count := range pa.RootWordsOriginal {
		combinedWords[word] = count
	}

	for word, count := range pa.HybridPartsOriginal {
		if existingCount, exists := combinedWords[word]; exists {
			combinedWords[word] = existingCount + count
		} else {
			combinedWords[word] = count
		}
	}

	results := pa.GetTopResults(combinedWords, limit)

	file, err := os.Create(outputDir + "/rootAndHybrid_words_origional_context.txt")
	if err != nil {
		log.Printf("Error creating rootAndHybrid_words_origional_context.txt: %v", err)
		return
	}
	defer file.Close()

	for i, result := range results {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

// Export compound words with original casing and delimiters
func (pa *PasswordAnalysis) exportCompoundWordsOriginalContext(outputDir string, limit int) {
	results := pa.GetTopResults(pa.CompoundWordsOriginal, limit)

	file, err := os.Create(outputDir + "/compound_words_origional_context.txt")
	if err != nil {
		log.Printf("Error creating compound_words_origional_context.txt: %v", err)
		return
	}
	defer file.Close()

	for i, result := range results {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

// Export top 100 compound words
func (pa *PasswordAnalysis) exportTop100CompoundWords(outputDir string) {
	compounds := pa.GetTopResults(pa.CompoundWords, 100)
	
	file, err := os.Create(outputDir + "/smallLists/top100_compound_words.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top100_compound_words.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range compounds {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

// Export top 100 numbers
func (pa *PasswordAnalysis) exportTop100Numbers(outputDir string) {
	numbers := pa.GetTopResults(pa.NumberPatterns, 100)
	
	file, err := os.Create(outputDir + "/smallLists/top100_numbers.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top100_numbers.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range numbers {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

// Export top 100 root and hybrid words
func (pa *PasswordAnalysis) exportTop100RootAndHybrid(outputDir string) {
	// Combine root words and hybrid parts into one unique map
	combinedWords := make(map[string]int)
	
	// Add root words
	for word, count := range pa.RootWords {
		combinedWords[word] = count
	}
	
	// Add hybrid parts, combining counts if word exists in both
	for word, count := range pa.HybridParts {
		if existingCount, exists := combinedWords[word]; exists {
			combinedWords[word] = existingCount + count
		} else {
			combinedWords[word] = count
		}
	}
	
	// Get top 100 results using the combined map
	results := pa.GetTopResults(combinedWords, 100)
	
	file, err := os.Create(outputDir + "/smallLists/top100_rootAndHybrid.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top100_rootAndHybrid.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range results {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

// Export top 1000 root and hybrid words
func (pa *PasswordAnalysis) exportTop1000RootAndHybrid(outputDir string) {
	// Combine root words and hybrid parts into one unique map
	combinedWords := make(map[string]int)
	
	// Add root words
	for word, count := range pa.RootWords {
		combinedWords[word] = count
	}
	
	// Add hybrid parts, combining counts if word exists in both
	for word, count := range pa.HybridParts {
		if existingCount, exists := combinedWords[word]; exists {
			combinedWords[word] = existingCount + count
		} else {
			combinedWords[word] = count
		}
	}
	
	// Get top 1000 results using the combined map
	results := pa.GetTopResults(combinedWords, 1000)
	
	file, err := os.Create(outputDir + "/smallLists/top1000_rootAndHybrid.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top1000_rootAndHybrid.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range results {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

// Export root and hybrid words with space suffix
func (pa *PasswordAnalysis) exportRootAndHybridWithSpace(outputDir string) {
	// Combine root words and hybrid parts into one unique map
	combinedWords := make(map[string]int)
	
	// Add root words
	for word, count := range pa.RootWords {
		combinedWords[word] = count
	}
	
	// Add hybrid parts, combining counts if word exists in both
	for word, count := range pa.HybridParts {
		if existingCount, exists := combinedWords[word]; exists {
			combinedWords[word] = existingCount + count
		} else {
			combinedWords[word] = count
		}
	}
	
	// Export top 100 with space suffix
	results100 := pa.GetTopResults(combinedWords, 100)
	file100, err := os.Create(outputDir + "/smallLists/top100_rootAndHybrid_space.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top100_rootAndHybrid_space.txt: %v", err)
	} else {
		defer file100.Close()
		for i, result := range results100 {
			if i > 0 {
				fmt.Fprintf(file100, "\n")
			}
			fmt.Fprintf(file100, "%s ", result.Pattern)
		}
	}
	
	// Export top 1000 with space suffix
	results1000 := pa.GetTopResults(combinedWords, 1000)
	file1000, err := os.Create(outputDir + "/smallLists/top1000_rootAndHybrid_space.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top1000_rootAndHybrid_space.txt: %v", err)
	} else {
		defer file1000.Close()
		for i, result := range results1000 {
			if i > 0 {
				fmt.Fprintf(file1000, "\n")
			}
			fmt.Fprintf(file1000, "%s ", result.Pattern)
		}
	}
}

// Export top 10000 root and hybrid words with space suffix
func (pa *PasswordAnalysis) exportTop10000RootAndHybridWithSpace(outputDir string) {
	// Combine root words and hybrid parts into one unique map
	combinedWords := make(map[string]int)
	
	// Add root words
	for word, count := range pa.RootWords {
		combinedWords[word] = count
	}
	
	// Add hybrid parts, combining counts if word exists in both
	for word, count := range pa.HybridParts {
		if existingCount, exists := combinedWords[word]; exists {
			combinedWords[word] = existingCount + count
		} else {
			combinedWords[word] = count
		}
	}
	
	// Export top 10000 with space suffix
	results := pa.GetTopResults(combinedWords, 10000)
	file, err := os.Create(outputDir + "/smallLists/top10000_rootAndHybrid_space.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top10000_rootAndHybrid_space.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range results {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s ", result.Pattern)
	}
}

// Export top 20000 root and hybrid words with space suffix
func (pa *PasswordAnalysis) exportTop20000RootAndHybridWithSpace(outputDir string) {
	// Combine root words and hybrid parts into one unique map
	combinedWords := make(map[string]int)
	
	// Add root words
	for word, count := range pa.RootWords {
		combinedWords[word] = count
	}
	
	// Add hybrid parts, combining counts if word exists in both
	for word, count := range pa.HybridParts {
		if existingCount, exists := combinedWords[word]; exists {
			combinedWords[word] = existingCount + count
		} else {
			combinedWords[word] = count
		}
	}
	
	// Export top 20000 with space suffix
	results := pa.GetTopResults(combinedWords, 20000)
	file, err := os.Create(outputDir + "/smallLists/top20000_rootAndHybrid_space.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top20000_rootAndHybrid_space.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range results {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s ", result.Pattern)
	}
}

// Export root and hybrid words with dash suffix
func (pa *PasswordAnalysis) exportRootAndHybridWithDash(outputDir string) {
	// Combine root words and hybrid parts into one unique map
	combinedWords := make(map[string]int)
	
	// Add root words
	for word, count := range pa.RootWords {
		combinedWords[word] = count
	}
	
	// Add hybrid parts, combining counts if word exists in both
	for word, count := range pa.HybridParts {
		if existingCount, exists := combinedWords[word]; exists {
			combinedWords[word] = existingCount + count
		} else {
			combinedWords[word] = count
		}
	}
	
	// Export top 100 with dash suffix
	results100 := pa.GetTopResults(combinedWords, 100)
	file100, err := os.Create(outputDir + "/smallLists/top100_rootAndHybrid_dash.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top100_rootAndHybrid_dash.txt: %v", err)
	} else {
		defer file100.Close()
		for i, result := range results100 {
			if i > 0 {
				fmt.Fprintf(file100, "\n")
			}
			fmt.Fprintf(file100, "%s-", result.Pattern)
		}
	}
	
	// Export top 1000 with dash suffix
	results1000 := pa.GetTopResults(combinedWords, 1000)
	file1000, err := os.Create(outputDir + "/smallLists/top1000_rootAndHybrid_dash.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top1000_rootAndHybrid_dash.txt: %v", err)
	} else {
		defer file1000.Close()
		for i, result := range results1000 {
			if i > 0 {
				fmt.Fprintf(file1000, "\n")
			}
			fmt.Fprintf(file1000, "%s-", result.Pattern)
		}
	}
}

// Export top 1000 compound words with spaces
func (pa *PasswordAnalysis) exportTop1000CompoundWordsWithSpaces(outputDir string) {
	compounds := pa.GetTopResults(pa.CompoundWords, 1000)
	
	file, err := os.Create(outputDir + "/smallLists/top1000_compound_words_spaces.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top1000_compound_words_spaces.txt: %v", err)
		return
	}
	defer file.Close()
	
	// Use a map to store unique entries and their frequencies
	uniqueEntries := make(map[string]int)
	
	for _, result := range compounds {
		pattern := result.Pattern
		
		// Only include multi-word entries (contains spaces and has at least 2 words)
		if strings.Contains(pattern, " ") {
			words := strings.Fields(pattern)
			if len(words) > 1 {
				// Generate only multi-word n-gram substrings (skip single words)
				for i := 0; i < len(words); i++ {
					for j := i + 2; j <= len(words); j++ { // Start from i+2 to ensure at least 2 words
						substring := strings.Join(words[i:j], " ") + " "
						// Add to unique entries, combining frequencies
						uniqueEntries[substring] += result.Count
					}
				}
				// Also add the full compound word with space suffix
				uniqueEntries[pattern+" "] += result.Count
			}
		}
		// Skip single word entries entirely
	}
	
	// Convert map back to slice and sort by frequency
	var sortedEntries []AnalysisResult
	for pattern, count := range uniqueEntries {
		sortedEntries = append(sortedEntries, AnalysisResult{
			Pattern: pattern,
			Count:   count,
		})
	}
	
	// Sort by count (descending)
	sort.Slice(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].Count > sortedEntries[j].Count
	})
	
	// Apply limit after processing
	if len(sortedEntries) > 1000 {
		sortedEntries = sortedEntries[:1000]
	}
	
	// Write to file
	for i, result := range sortedEntries {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

// Export top 10000 compound words with spaces
func (pa *PasswordAnalysis) exportTop10000CompoundWordsWithSpaces(outputDir string) {
	compounds := pa.GetTopResults(pa.CompoundWords, 10000)
	
	file, err := os.Create(outputDir + "/smallLists/top10000_compound_words_spaces.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top10000_compound_words_spaces.txt: %v", err)
		return
	}
	defer file.Close()
	
	// Use a map to store unique entries and their frequencies
	uniqueEntries := make(map[string]int)
	
	for _, result := range compounds {
		pattern := result.Pattern
		
		// Only include multi-word entries (contains spaces and has at least 2 words)
		if strings.Contains(pattern, " ") {
			words := strings.Fields(pattern)
			if len(words) > 1 {
				// Generate only multi-word n-gram substrings (skip single words)
				for i := 0; i < len(words); i++ {
					for j := i + 2; j <= len(words); j++ { // Start from i+2 to ensure at least 2 words
						substring := strings.Join(words[i:j], " ") + " "
						// Add to unique entries, combining frequencies
						uniqueEntries[substring] += result.Count
					}
				}
				// Also add the full compound word with space suffix
				uniqueEntries[pattern+" "] += result.Count
			}
		}
		// Skip single word entries entirely
	}
	
	// Convert map back to slice and sort by frequency
	var sortedEntries []AnalysisResult
	for pattern, count := range uniqueEntries {
		sortedEntries = append(sortedEntries, AnalysisResult{
			Pattern: pattern,
			Count:   count,
		})
	}
	
	// Sort by count (descending)
	sort.Slice(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].Count > sortedEntries[j].Count
	})
	
	// Apply limit after processing
	if len(sortedEntries) > 10000 {
		sortedEntries = sortedEntries[:10000]
	}
	
	// Write to file
	for i, result := range sortedEntries {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

// Export top 20000 compound words with spaces
func (pa *PasswordAnalysis) exportTop20000CompoundWordsWithSpaces(outputDir string) {
	compounds := pa.GetTopResults(pa.CompoundWords, 20000)
	
	file, err := os.Create(outputDir + "/smallLists/top20000_compound_words_spaces.txt")
	if err != nil {
		log.Printf("Error creating smallLists/top20000_compound_words_spaces.txt: %v", err)
		return
	}
	defer file.Close()
	
	// Use a map to store unique entries and their frequencies
	uniqueEntries := make(map[string]int)
	
	for _, result := range compounds {
		pattern := result.Pattern
		
		// Only include multi-word entries (contains spaces and has at least 2 words)
		if strings.Contains(pattern, " ") {
			words := strings.Fields(pattern)
			if len(words) > 1 {
				// Generate only multi-word n-gram substrings (skip single words)
				for i := 0; i < len(words); i++ {
					for j := i + 2; j <= len(words); j++ { // Start from i+2 to ensure at least 2 words
						substring := strings.Join(words[i:j], " ") + " "
						// Add to unique entries, combining frequencies
						uniqueEntries[substring] += result.Count
					}
				}
				// Also add the full compound word with space suffix
				uniqueEntries[pattern+" "] += result.Count
			}
		}
		// Skip single word entries entirely
	}
	
	// Convert map back to slice and sort by frequency
	var sortedEntries []AnalysisResult
	for pattern, count := range uniqueEntries {
		sortedEntries = append(sortedEntries, AnalysisResult{
			Pattern: pattern,
			Count:   count,
		})
	}
	
	// Sort by count (descending)
	sort.Slice(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].Count > sortedEntries[j].Count
	})
	
	// Apply limit after processing
	if len(sortedEntries) > 20000 {
		sortedEntries = sortedEntries[:20000]
	}
	
	// Write to file
	for i, result := range sortedEntries {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) exportAdaptiveMarkovChains(outputDir string, limit int) {
	// pa.exportAdaptiveVariableLengthChains(outputDir, limit)
	pa.exportAdaptivePositionSpecificChains(outputDir, limit)
	// pa.exportAdaptiveContextAwareChains(outputDir, limit)
}

func (pa *PasswordAnalysis) exportAdaptiveVariableLengthChains(outputDir string, limit int) {
	var chains []AnalysisResult
	for prefix, suffixes := range pa.AdaptiveChains {
		for suffix, freq := range suffixes {
			if freq >= pa.MinFreq {
				chains = append(chains, AnalysisResult{
					Pattern: prefix + suffix,
					Count:   freq,
				})
			}
		}
	}
	
	sort.Slice(chains, func(i, j int) bool {
		return chains[i].Count > chains[j].Count
	})
	
	if len(chains) > limit {
		chains = chains[:limit]
	}
	
	file, err := os.Create(outputDir + "/markov/markov_adaptive_variable.txt")
	if err != nil {
		log.Printf("Error creating markov/markov_adaptive_variable.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range chains {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) exportAdaptivePositionSpecificChains(outputDir string, limit int) {
	positions := []string{"start", "end"}
	
	for _, position := range positions {
		if chains, exists := pa.PositionSpecificChains[position]; exists {
			var positionChains []AnalysisResult
			for prefix, suffixes := range chains {
				for suffix, freq := range suffixes {
					if freq >= pa.MinFreq {
						positionChains = append(positionChains, AnalysisResult{
							Pattern: prefix + suffix,
							Count:   freq,
						})
					}
				}
			}
			
			sort.Slice(positionChains, func(i, j int) bool {
				return positionChains[i].Count > positionChains[j].Count
			})
			
			if len(positionChains) > limit {
				positionChains = positionChains[:limit]
			}
			
			filename := fmt.Sprintf("%s/markov/markov_adaptive_%s.txt", outputDir, position)
			file, err := os.Create(filename)
			if err != nil {
				log.Printf("Error creating %s: %v", filename, err)
				continue
			}
			defer file.Close()
			
			for i, result := range positionChains {
				if i > 0 {
					fmt.Fprintf(file, "\n")
				}
				fmt.Fprintf(file, "%s", result.Pattern)
			}
		}
	}
}

func (pa *PasswordAnalysis) exportAdaptiveContextAwareChains(outputDir string, limit int) {
	var contextChains []AnalysisResult
	for contextKey, suffixes := range pa.ContextAwareChains {
		for suffix, freq := range suffixes {
			if freq >= pa.MinFreq {
				contextChains = append(contextChains, AnalysisResult{
					Pattern: contextKey + ">" + suffix,
					Count:   freq,
				})
			}
		}
	}
	
	sort.Slice(contextChains, func(i, j int) bool {
		return contextChains[i].Count > contextChains[j].Count
	})
	
	if len(contextChains) > limit {
		contextChains = contextChains[:limit]
	}
	
	file, err := os.Create(outputDir + "/markov/markov_adaptive_context.txt")
	if err != nil {
		log.Printf("Error creating markov/markov_adaptive_context.txt: %v", err)
		return
	}
	defer file.Close()
	
	for i, result := range contextChains {
		if i > 0 {
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "%s", result.Pattern)
	}
}

func (pa *PasswordAnalysis) PrintAnalysisReport() {
	fmt.Printf("Password Analysis Report\n")
	fmt.Printf("========================\n")
	fmt.Printf("Total passwords analyzed: %d\n", pa.TotalPasswords)
	fmt.Printf("Minimum frequency threshold: %d\n\n", pa.MinFreq)
	
	fmt.Printf("Analysis Categories:\n")
	fmt.Printf("- Root words: %d unique\n", len(pa.RootWords))
	fmt.Printf("- Case patterns: %d unique\n", len(pa.CasePatterns))
	fmt.Printf("- Year patterns: %d unique\n", len(pa.YearPatterns))
	fmt.Printf("- Number patterns: %d unique\n", len(pa.NumberPatterns))
	fmt.Printf("- Date patterns: %d unique\n", len(pa.DatePatterns))
	fmt.Printf("- Substitution patterns: %d unique\n", len(pa.Substitutions))
	fmt.Printf("- Keyboard walks: %d unique\n", len(pa.KeyboardWalks))
	totalNGrams := 0
	for n := 5; n <= 7; n++ {
		if ngramsMap, exists := pa.NGrams[n]; exists {
			totalNGrams += len(ngramsMap)
		}
	}
	fmt.Printf("- N-grams (5-7): %d unique\n", totalNGrams)
	fmt.Printf("- Hybrid parts: %d unique\n", len(pa.HybridParts))
	fmt.Printf("- Language patterns: %d unique\n", len(pa.LanguagePatterns))
	fmt.Printf("- Temporal patterns: %d unique\n", len(pa.TemporalPatterns))
	fmt.Printf("- Compound words: %d unique\n", len(pa.CompoundWords))
	fmt.Printf("- Word separators: %d unique\n", len(pa.WordSeparators))
	fmt.Printf("- Domain patterns: %d unique\n", len(pa.DomainPatterns))
	// fmt.Printf("- Reversed passwords: %d unique\n", len(pa.ReversedPasswords))
	// fmt.Printf("- Reversed keywords: %d unique\n", len(pa.ReversedKeywords))
	// fmt.Printf("- Reversed compound words: %d unique\n", len(pa.ReversedCompoundWords))
	
	totalMarkovChains := 0
	for n := 7; n <= 10; n++ {
		if chains, exists := pa.MarkovChains[n]; exists {
			totalMarkovChains += len(chains)
		}
	}
	fmt.Printf("- Markov chains (7-10gram): %d unique\n", totalMarkovChains)
	
	totalAdaptiveChains := len(pa.AdaptiveChains)
	totalPositionChains := 0
	for _, chains := range pa.PositionSpecificChains {
		totalPositionChains += len(chains)
	}
	totalContextChains := len(pa.ContextAwareChains)
	fmt.Printf("- Adaptive chains: %d unique\n", totalAdaptiveChains)
	fmt.Printf("- Position-specific chains: %d unique\n", totalPositionChains)
	fmt.Printf("- Context-aware chains: %d unique\n", totalContextChains)
	
	fmt.Printf("\nTop 10 Root Words:\n")
	rootWords := pa.GetTopResults(pa.RootWords, 10)
	for i, result := range rootWords {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	fmt.Printf("\nTop 10 Year Patterns:\n")
	years := pa.GetTopResults(pa.YearPatterns, 10)
	for i, result := range years {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	fmt.Printf("\nTop 10 Number Patterns:\n")
	numbers := pa.GetTopResults(pa.NumberPatterns, 10)
	for i, result := range numbers {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	fmt.Printf("\nTop 10 Date Patterns:\n")
	dates := pa.GetTopResults(pa.DatePatterns, 10)
	for i, result := range dates {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	
	fmt.Printf("\nTop 5 Language Patterns:\n")
	languages := pa.GetTopResults(pa.LanguagePatterns, 5)
	for i, result := range languages {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	fmt.Printf("\nTop 10 Temporal Patterns:\n")
	temporal := pa.GetTopResults(pa.TemporalPatterns, 10)
	for i, result := range temporal {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	fmt.Printf("\nTop 5 Domain Patterns:\n")
	domains := pa.GetTopResults(pa.DomainPatterns, 5)
	for i, result := range domains {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	fmt.Printf("\nTop 10 Word Separators:\n")
	separators := pa.GetTopResults(pa.WordSeparators, 10)
	for i, result := range separators {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	fmt.Printf("\nAll Language Patterns:\n")
	allLanguages := pa.GetTopResults(pa.LanguagePatterns, 1000)
	for i, result := range allLanguages {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	fmt.Printf("\nAll Temporal Patterns:\n")
	allTemporal := pa.GetTopResults(pa.TemporalPatterns, 1000)
	for i, result := range allTemporal {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	fmt.Printf("\nAll Domain Patterns:\n")
	allDomains := pa.GetTopResults(pa.DomainPatterns, 1000)
	for i, result := range allDomains {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
	
	fmt.Printf("\nAll Word Separators:\n")
	allSeparators := pa.GetTopResults(pa.WordSeparators, 1000)
	for i, result := range allSeparators {
		fmt.Printf("%2d. %-15s (%d)\n", i+1, result.Pattern, result.Count)
	}
}

func main() {
	fmt.Printf("PhurtimCrackedAnalyzer %s - Password Pattern Analysis Tool\n", VERSION)
	fmt.Printf("========================================================\n\n")
	
	if len(os.Args) < 5 {
		fmt.Printf("Usage: %s <password_file> <output_dir> <min_frequency> <min_num_length> [max_results]\n", os.Args[0])
		fmt.Printf("  password_file: Path to password file to analyze\n")
		fmt.Printf("  output_dir: Directory to save wordlists and rules\n")
		fmt.Printf("  min_frequency: Minimum frequency threshold\n")
		fmt.Printf("  min_num_length: Minimum length for number patterns (e.g., 2 to skip single digits)\n")
		fmt.Printf("  max_results: Maximum results per category (default: 1000)\n")
		os.Exit(1)
	}
	
	filename := os.Args[1]
	outputDir := os.Args[2]
	
	minFreq, err := strconv.Atoi(os.Args[3])
	if err != nil || minFreq <= 0 {
		fmt.Printf("Error: min_frequency must be a positive integer\n")
		os.Exit(1)
	}
	
	minNumLength, err := strconv.Atoi(os.Args[4])
	if err != nil || minNumLength <= 0 {
		fmt.Printf("Error: min_num_length must be a positive integer\n")
		os.Exit(1)
	}
	
	maxResults := 1000
	if len(os.Args) > 5 {
		maxResults, err = strconv.Atoi(os.Args[5])
		if err != nil || maxResults <= 0 {
			fmt.Printf("Error: max_results must be a positive integer\n")
			os.Exit(1)
		}
	}
	
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	// Read all passwords into memory
	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pw := strings.TrimSpace(scanner.Text())
		if pw != "" {
			passwords = append(passwords, pw)
		}
	}
	file.Close()
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Loaded %d passwords, analyzing with %d workers...\n", len(passwords), runtime.NumCPU())

	// Parallel analysis
	numWorkers := runtime.NumCPU()
	ch := make(chan string, 256)
	workers := make([]*PasswordAnalysis, numWorkers)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		workers[i] = NewPasswordAnalysis(minFreq, minNumLength)
		wg.Add(1)
		go func(pa *PasswordAnalysis) {
			defer wg.Done()
			for password := range ch {
				pa.AnalyzePassword(password)
			}
		}(workers[i])
	}

	for _, pw := range passwords {
		ch <- pw
	}
	close(ch)
	wg.Wait()

	// Merge all workers into the first
	analysis := workers[0]
	for i := 1; i < numWorkers; i++ {
		analysis.Merge(workers[i])
	}
	
	analysis.PrintAnalysisReport()
	analysis.ExportWordlists(outputDir, maxResults)
	
	fmt.Printf("\nWordlists and rules exported to: %s\n", outputDir)
}