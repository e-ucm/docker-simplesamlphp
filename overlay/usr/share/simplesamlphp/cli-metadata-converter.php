<?php

require_once(__DIR__ . '/lib/_autoload.php');

use SimpleSAML\Utils;
use SimpleSAML\Metadata\SAMLParser;
use Symfony\Component\VarExporter\VarExporter;

function usage()
{
    fwrite(STDERR, "Usage: '.$args[0] . ' [-h | --help] [-f | --file]\n\n");
    fwrite(STDERR, "Converts SAML2 XML metadata to the PHP code used by SimpleSAMLphp. If -f or --file are\n");
    fwrite(STDERR, "not provided stdin it is used as metadata source.\n\n");
    fwrite(STDERR, "Options:\n");
    fwrite(STDERR, "\t-f metadata-file, --file=metadata-file\n");
    fwrite(STDERR, "\t\tReads the metadata from the provided file.\n");
    exit(0);
}

/**
 * Metadata converter
 *
 * @param string metadata to convert
 *
 * @see https://github.com/simplesamlphp/simplesamlphp/blob/master/modules/admin/lib/Controller/Federation.php
 */
function metadataConverter(string $xmldata)
{

    $xmldata = trim($xmldata);

    if (!empty($xmldata)) {
        Utils\XML::checkSAMLMessage($xmldata, 'saml-meta');
        $entities = SAMLParser::parseDescriptorsString($xmldata);

        // get all metadata for the entities
        foreach ($entities as &$entity) {
            $entity = [
                'shib13-sp-remote'  => $entity->getMetadata1xSP(),
                'shib13-idp-remote' => $entity->getMetadata1xIdP(),
                'saml20-sp-remote'  => $entity->getMetadata20SP(),
                'saml20-idp-remote' => $entity->getMetadata20IdP(),
            ];
        }

        // transpose from $entities[entityid][type] to $output[type][entityid]
        $output = Utils\Arrays::transpose($entities);

        // merge all metadata of each type to a single string which should be added to the corresponding file
        foreach ($output as $type => &$entities) {
            $text = '';
            foreach ($entities as $entityId => $entityMetadata) {
                if ($entityMetadata === null) {
                    continue;
                }

                /**
                 * remove the entityDescriptor element because it is unused,
                 * and only makes the output harder to read
                 */
                unset($entityMetadata['entityDescriptor']);

                $text .= '$metadata[' . var_export($entityId, true) . '] = '
                    . var_export($entityMetadata, true) . ";\n";
            }
            $entities = $text;
        }
    } else {
        $xmldata = '';
        $output = [];
    }

    return $output;
}

// Script example.php
$shortopts  = "hf:";

$longopts  = array(
    "file:",
    "help",
);
$options = getopt($shortopts, $longopts);

if (isset($options['h']) || isset($options['help']) ) {
    usage();
}

$xmldata = '';

if ( isset($options['f']) ) {
    $xmldata = file_get_contents($options['f']);
} else if ( isset($options['file']) ) {
    $xmldata = file_get_contents($options['file']);
} else {
    fwrite(STDERR, "Reading metadata from stdin\n");
    $xmldata = file_get_contents('php://stdin');
}

$metadata=metadataConverter($xmldata);
$metadata = $metadata['saml20-idp-remote'];
print_r($metadata);