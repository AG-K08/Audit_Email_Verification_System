rule TestRule
{
    strings:
        $test = "test"

    condition:
        $test
}