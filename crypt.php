<?php

ini_set('memory_limit', '-1');

define('DS', '\\');

function try_get($o, $a, $d = null)
{
    if(isset($o[$a]))
    {
        return $o[$a];
    }
    else if(isset($o->$a))
    {
        return $o->$a;
    }

    return $d;
}

function output($message)
{
    echo $message . "\n";
}

function str_inverse($str)
{
    $strLen = strlen($str);

    for($i = 0; $i < $strLen; $i++)
    {
        $str[$i] = chr(-ord($str[$i]));
    }

    return $str;
}

function str_reverse($string)
{
    $result = '';

    for($i = strlen($string) - 1; $i >= 0; $i--)
    {
        $result .= $string[$i];
    }

    return $result;
}

function factorial($n)
{
    $r = 1;

    for($i = $n; $i > 0; $i--)
    {
        $r *= $i;
    }

    return $r;
}

function array_first($a)
{
    return empty($a) || !is_array($a) ? null : $a[array_keys($a)[0]];
}

const MAX_WORD_LEN   = 10;

class ProgressBar {

    public function __construct($length = 10, $spinner = null)
    {
        if(!is_array($spinner))
        {
            $spinner = [
                '-',
                '/',
                '|',
                '\\',
            ];
        }

        $this->length = $length;
        $this->setSpinner($spinner);
    }

    public function setSpinner($spinner)
    {
        $this->spinner      = $spinner;
        $this->spinnerCount = count($spinner);
    }

    public function getSpinnerChar()
    {
        if(!isset($this->spinnerI))
        {
            return null;
        }

        return $this->spinner[$this->spinnerI % $this->spinnerCount];
    }

    public function nextSpinnerChar()
    {
        $this->spinnerI++;
    }

    public function start($expectedCount, $message = '')
    {
        if(!is_numeric($expectedCount))
        {
            throw new \Exception('Expected Count is not numeric!');
        }
        if(!is_string($message))
        {
            throw new \Exception('Message is not a string!');
        }

        $this->lastProgress  = 0;
        $this->lastTime      = time();
        $this->spinnerI      = 0;
        $this->expectedCount = $expectedCount;
        $this->message       = $message;
        $this->startTime     = time();
    }

    public function update($currentCount)
    {
        $progress    = floor(min(($currentCount / $this->expectedCount) * $this->length, $this->length));
        $remaining   = $this->length - $progress;
        $progressBar = str_repeat('*', $progress) . str_repeat($this->getSpinnerChar(), $remaining);

        if($this->lastProgress !== $progress || $this->lastTime !== time())
        {
            $time = time() - $this->startTime;

            echo $this->message . $progressBar . " ({$time}s)" . "\r";
            $this->nextSpinnerChar();
        }

        $this->lastProgress = $progress;
        $this->lastTime     = time();
    }

    public function end()
    {
        $time = time() - $this->startTime;

        echo "\r" . str_repeat(' ', $this->length + strlen($this->message) + strlen(" ({$time}s)")) . "\r";

        return time() - $this->startTime;
    }

}

class Encryption {

    /**
    * Signature
    *
    * @var string
    */
    public $signature  = '{--decrypt(?)} {--base64(?)} {fileName(1)} {outFile(2)} {key(3)}';

    /**
    * Progress Bar
    *
    * @var ProgressBar
    */
    public $progressBar;

    /**
    * Constructor
    *
    * @param string $commandName
    */
    public function __construct($commandName)
    {
        $this->commandName = $commandName;
        $this->progressBar = new ProgressBar();
    }

    /**
    * Display Signature
    */
    public function displaySignature()
    {
        output('Arguments with (?) are optional');
        output($this->commandName . ': ' . $this->signature);
        die;
    }

    /**
    * Generate Word Combinations
    *
    * @param array $words
    * @param int $depth
    * @return array
    */
    public function wordCombos($words, $depth = 0, $firstCall = true)
    {
        $result = [];

        if($depth === 0 && $firstCall)
        {
            $this->wordCount = 0;

            $totalWordCount = factorial(count($words));

            $this->progressBar->start($totalWordCount, 'Generating Key Combinations: ');
        }

        if($depth === 0 && $firstCall && count($words) > MAX_WORD_LEN)
        {
            $words          = array_chunk($words, MAX_WORD_LEN);
            $totalWordCount = 0;

            foreach($words as $sWords)
            {
                $totalWordCount += factorial(count($sWords));
            }

            $this->progressBar->start($totalWordCount, 'Generating Key Combinations: ');

            foreach($words as $sWords)
            {
                $result = array_merge($result, $this->wordCombos($sWords, $depth, false));
            }
        }
        else
        {
            if (count($words) <= 1)
            {
                $result = $words;
            }
            else
            {
                $result = array();

                for($i = 0; $i < count($words); ++$i)
                {
                    $firstword      = $words[$i];
                    $remainingwords = array();

                    for($j = 0; $j < count($words); ++$j)
                    {
                        if($i <> $j)
                        {
                            $remainingwords[] = $words[$j];
                        }
                    }

                    $combos = $this->wordCombos($remainingwords, $depth + 1, false);

                    for($j = 0; $j < count($combos); ++$j)
                    {
                        if($depth === 0)
                        {
                            $this->wordCount++;
                        }

                        $this->progressBar->update($this->wordCount);

                        $result[] = $firstword  . $combos[$j];
                    }
                }
            }
        }

        if($depth === 0 && $firstCall)
        {
            $time = $this->progressBar->end();

            $keyHashCount = count($result);

            output("Generated Key Combinations Count ($keyHashCount) ({$time}s)");
        }

        return $result;
    }

    /**
    * Generate Key Hashes
    *
    * @param array $keyHashes
    * @return array
    */
    public function generateKeyHashes($keyHashes)
    {
        $keyHashCount   = count($keyHashes);
        $keyHashI       = 0;

        $this->progressBar->start($keyHashCount, 'Generating Key Hashes: ');

        $keyHashes = array_map(function($key) use(&$keyHashI)
        {
            $this->progressBar->update($keyHashI++);

            return md5($key) . md5(str_reverse($key)) . md5(str_reverse(str_inverse($key))) . md5(str_reverse(str_inverse(str_reverse($key))));
        }, $keyHashes);

        $time           = $this->progressBar->end();
        $keyHashCount   = array_sum(array_map('strlen', $keyHashes));

        output("Generated Keyhash Length ($keyHashCount) ({$time}s)");

        return $keyHashes;
    }

    /**
    * Interlace Key Hashes
    *
    * @param array $keyHashes
    * @return string
    */
    public function interlaceKeyHashes($keyHashes)
    {
        $result         = '';
        $keyHashI       = 0;
        $keyHashLength  = strlen(array_first($keyHashes));
        $totalHashLen   = $keyHashLength * count($keyHashes);

        $this->progressBar->start(min($totalHashLen, $this->length), 'Interlacing Key Hashes: ');

        for($j = 0; $j < $keyHashLength && $keyHashI < $this->length; $j++)
        {
            for($i = 0; $i < count($keyHashes) && $keyHashI < $this->length; $i++)
            {
                $result .= $keyHashes[$i][$j];

                $this->progressBar->update($keyHashI++);
            }
        }

        $time = $this->progressBar->end();

        output("Interlaced Key Hashes ({$time}s)");

        return $result;
    }

    /**
    * Validate Arguments
    *
    * @param string $fileName
    * @param string $outFile
    * @param string $key
    */
    public function validateArgs($fileName, $outFile, $key)
    {
        if(!isset($fileName))
        {
            output('No {fileName(1)} provided');
            return false;
        }
        else if(!file_exists($fileName))
        {
            output('No file with {fileName(1)} exists');
            return false;
        }

        if(!isset($outFile))
        {
            output('No {outFile(2)} provided');
            return false;
        }

        if(!isset($key))
        {
            output('No {key(3)} provided');
            return false;
        }

        return true;
    }

    /**
    * Run Encryption Protocol
    *
    * @param boolean $decrypt
    * @param boolean $base64
    * @param string $fileName
    * @param string $outFile
    * @param string $key
    */
    public function run($decrypt, $base64, $fileName, $outFile, $key)
    {
        $totalTime = time();

        // ----------------- Checking Arguments ---------------------

        if($this->validateArgs($fileName, $outFile, $key) === false)
        {
            return false;
        }

        output("File '$fileName' found");

        $nullFileExt   = '__--null--__';
        $extentionPre  = '::::::';
        $fileExtention = $decrypt ? $nullFileExt : pathinfo($fileName, PATHINFO_EXTENSION);
        $file          = ($decrypt ? '' : ($fileExtention . $extentionPre)) . file_get_contents($fileName);
        $file          = $decrypt && $base64 ? base64_decode($file) : $file;
        $this->length  = strlen($file);

        output(($decrypt ? 'Decrypting' : 'Encrypting') . " '$fileName' with key '$key'");

        // ----------------- Key Combination Generation ---------------------

        $keyHashes      = $this->wordCombos(str_split($key));

        // ----------------- Key Hash Generation ---------------------

        $keyHashes      = $this->generateKeyHashes($keyHashes);

        // ----------------- Key Hash Interlacing ---------------------

        $keyHash        = $this->interlaceKeyHashes($keyHashes);

        // ----------------- Decode / Encode ---------------------

        $keyHashCount   = strlen($keyHash);
        $encryptingMsg  = ($decrypt ? 'Decrypting' : 'Encrypting');
        $encryptedMsg   = ($decrypt ? 'Decrypted' : 'Encrypted');

        $this->progressBar->start($this->length, "$encryptingMsg: ");

        for($i = 0; $i < $this->length; $i++)
        {
            $orig = $file[$i];
            $hash = $keyHash[$i % $keyHashCount];
            $char = chr($decrypt ? ord($orig) - ord($hash) : ord($orig) + ord($hash));

            $file[$i] = $char;

            $this->progressBar->update($i);
        }

        $time = $this->progressBar->end();

        // ----------------- Validity Check ---------------------

        $file = $decrypt || !$base64 ? $file : base64_encode($file);

        if($decrypt)
        {
            $fileExtentionPos = strpos($file, $extentionPre);

            if($fileExtentionPos === false || $fileExtentionPos > 260)
            {
                output("Failed to decrypt file");
                return null;
            }

            $fileExtention = substr($file, 0, $fileExtentionPos);

            if($fileExtention === $nullFileExt)
            {
                $fileExtention = null;
            }

            $file    = substr($file, $fileExtentionPos + strlen($extentionPre));
            $outFile = $outFile . (empty($fileExtention) ? '' : ('.' . $fileExtention));
        }

        file_put_contents($outFile, $file);

        $totalTime = time() - $totalTime;

        output("Successfully $encryptedMsg '$fileName' => '$outFile' ({$time}s) (Total ({$totalTime}s))");

        return true;
    }
}

// ----------------- Main Program ---------------------

$result     = false;
$encryption = new Encryption($argv[0]);

$args     = array_slice($argv, 1);
$decrypt  = try_get($args, 0) === "--decrypt" ? (function()use(&$args){$args = array_slice($args, 1); return 1;})() : 0;
$base64   = try_get($args, 0) === "--base64" ? (function()use(&$args){$args = array_slice($args, 1); return 1;})() : 0;
$fileName = try_get($args, 0);
$outFile  = try_get($args, 1);
$key      = try_get($args, 2);

$result = $encryption->run($decrypt, $base64, $fileName, $outFile, $key);

if($result === false)
{
    $encryption->displaySignature();
}
