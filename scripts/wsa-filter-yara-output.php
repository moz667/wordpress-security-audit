<?php

if ($argc !== 3 || $argv[1] !== '--eligible-files') {
    fwrite(STDERR, "Usage: php wsa-filter-yara-output.php --eligible-files <yara-output>\n");
    exit(2);
}

$inputPath = $argv[2];
$input = @fopen($inputPath, 'rb');
if ($input === false) {
    fwrite(STDERR, "Error: cannot read YARA output: $inputPath\n");
    exit(1);
}

function isPrintableUtf8Triplet($file, $offset, $length)
{
    if ($length < 3 || fseek($file, 0, SEEK_END) !== 0) {
        throw new RuntimeException('Invalid YARA match range');
    }

    $fileSize = ftell($file);
    if ($fileSize === false || $offset + $length > $fileSize) {
        throw new RuntimeException('Matched file changed or could not be inspected');
    }

    $targetStart = $offset + $length - 3;
    $targetEnd = $targetStart + 3;
    $contextStart = max(0, $targetStart - 3);
    $contextEnd = min($fileSize, $targetEnd + 3);

    if (fseek($file, $contextStart) !== 0) {
        throw new RuntimeException('Could not seek to matched bytes');
    }
    $context = fread($file, $contextEnd - $contextStart);
    if ($context === false || strlen($context) !== $contextEnd - $contextStart) {
        throw new RuntimeException('Could not read matched bytes');
    }

    $targetStartInContext = $targetStart - $contextStart;
    $targetEndInContext = $targetEnd - $contextStart;
    $maxLeftTrim = min(3, $targetStartInContext);
    $maxRightTrim = min(3, strlen($context) - $targetEndInContext);

    for ($leftTrim = 0; $leftTrim <= $maxLeftTrim; $leftTrim++) {
        for ($rightTrim = 0; $rightTrim <= $maxRightTrim; $rightTrim++) {
            $candidate = substr($context, $leftTrim, strlen($context) - $leftTrim - $rightTrim);
            if ($candidate === '' || preg_match('//u', $candidate) !== 1) {
                continue;
            }

            $candidateStart = $contextStart + $leftTrim;
            $candidateEnd = $candidateStart + strlen($candidate);
            if ($candidateStart > $targetStart || $candidateEnd < $targetEnd) {
                continue;
            }

            $cursor = $candidateStart;
            $allPrintable = true;
            foreach (preg_split('//u', $candidate, -1, PREG_SPLIT_NO_EMPTY) as $character) {
                $characterEnd = $cursor + strlen($character);
                if ($cursor < $targetEnd && $characterEnd > $targetStart
                    && preg_match('/[\p{C}\p{Zl}\p{Zp}]/u', $character) === 1) {
                    $allPrintable = false;
                    break;
                }
                $cursor = $characterEnd;
            }

            if ($allPrintable) {
                return true;
            }
        }
    }

    return false;
}

$files = [];
$currentRule = null;
$currentFile = null;

while (($line = fgets($input)) !== false) {
    $line = rtrim($line, "\r\n");
    if (preg_match('/^0x([[:xdigit:]]+):([0-9]+):(\$[A-Za-z0-9_]+):/', $line, $match) === 1) {
        if ($currentFile === null || !isset($files[$currentFile])) {
            fwrite(STDERR, "Error: YARA string match found without a rule header\n");
            fclose($input);
            exit(1);
        }

        if ($currentRule !== 'NonPrintableChars' || $match[3] !== '$non_printables') {
            $files[$currentFile]['eligible'] = false;
            continue;
        }

        $files[$currentFile]['hit_count']++;
        $file = @fopen($currentFile, 'rb');
        if ($file === false) {
            fwrite(STDERR, "Error: cannot read matched file: $currentFile\n");
            fclose($input);
            exit(1);
        }
        try {
            $printable = isPrintableUtf8Triplet($file, hexdec($match[1]), (int)$match[2]);
        } catch (RuntimeException $error) {
            fwrite(STDERR, "Error: {$error->getMessage()} in $currentFile\n");
            fclose($file);
            fclose($input);
            exit(1);
        }
        fclose($file);
        if (!$printable) {
            $files[$currentFile]['eligible'] = false;
        }
        continue;
    }

    if (preg_match('/^([A-Za-z_][A-Za-z0-9_]*) (.+)$/', $line, $header) === 1) {
        $currentRule = $header[1];
        $currentFile = $header[2];
        if (!isset($files[$currentFile])) {
            $files[$currentFile] = [
                'eligible' => true,
                'hit_count' => 0,
            ];
        }
        if ($currentRule !== 'NonPrintableChars') {
            $files[$currentFile]['eligible'] = false;
        }
        continue;
    }

    if ($line !== '') {
        fwrite(STDERR, "Error: unrecognized YARA output line: $line\n");
        fclose($input);
        exit(1);
    }
}

if (!feof($input)) {
    fwrite(STDERR, "Error: failed while reading YARA output\n");
    fclose($input);
    exit(1);
}
fclose($input);

foreach ($files as $path => $result) {
    if ($result['eligible'] && $result['hit_count'] > 0) {
        echo $path, "\n";
    }
}
