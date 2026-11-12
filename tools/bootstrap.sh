#!/usr/bin/env bash
# bootstrap.sh — Installe l'outillage Java Card nécessaire au projet, dans .tools/ :
#   1. le kit Java Card 3.0.5u4 (API + convertisseur), depuis martinpaljak/oracle_javacard_sdks ;
#   2. jCardSim 3.0.5, compilé depuis ses sources et installé dans le dépôt Maven local
#      (il n'est pas publié sur Maven Central) ;
#   3. ant-javacard, qui pilote le convertisseur pour produire le fichier .cap.
#
# Toutes les versions sont épinglées. Le script est idempotent : relancez-le sans risque.
set -euo pipefail

cd "$(dirname "$0")/.."
TOOLS="$PWD/.tools"

SDKS_REPO=https://github.com/martinpaljak/oracle_javacard_sdks.git
SDKS_COMMIT=700ec80afdda210a0e62fb6a151a9cddc1acd244
JC_KIT=jc305u4_kit

JCARDSIM_REPO=https://github.com/licel/jcardsim.git
JCARDSIM_COMMIT=41511ec2a3d3dfa7a5fe2d07f5b4e56bc9c8dd56
JCARDSIM_VERSION=3.0.5-SNAPSHOT

ANT_JAVACARD_VERSION=v26.05.15
ANT_JAVACARD_SHA256=14f5e25c07b184e4ec02ee148892c2ea7ad5d7e9db8b91109524df8f7d000589

M2_REPO="${M2_REPO:-$HOME/.m2/repository}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

command -v java >/dev/null || { echo "Java introuvable : installez openjdk-11-jdk." >&2; exit 1; }
command -v mvn  >/dev/null || { echo "Maven introuvable : installez maven." >&2; exit 1; }
command -v git  >/dev/null || { echo "git introuvable." >&2; exit 1; }

mkdir -p "$TOOLS"

# 1. Kit Java Card (seul le dossier du kit utilisé est extrait)
if [[ ! -f "$TOOLS/sdks/$JC_KIT/lib/api_classic.jar" ]]; then
  log "Kit Java Card $JC_KIT"
  rm -rf "$TOOLS/sdks"
  git clone --quiet --filter=blob:none --no-checkout "$SDKS_REPO" "$TOOLS/sdks"
  git -C "$TOOLS/sdks" sparse-checkout set "$JC_KIT"
  git -C "$TOOLS/sdks" checkout --quiet "$SDKS_COMMIT"
else
  log "Kit Java Card déjà présent"
fi

# 2. API Java Card dans le dépôt Maven local.
# jCardSim (et donc ce projet, par dépendance transitive) dépend de
# oracle.javacard:api_classic:3.0.5, absent de Maven Central. On l'installe depuis le kit,
# en purgeant un éventuel échec mis en cache. Vérifié indépendamment de jCardSim : en CI,
# jCardSim peut revenir du cache alors que le dépôt Maven, lui, est neuf.
API_JAR="$M2_REPO/oracle/javacard/api_classic/3.0.5/api_classic-3.0.5.jar"
if [[ ! -f "$API_JAR" ]]; then
  log "Installation de l'API Java Card dans le dépôt Maven local"
  rm -f "$M2_REPO"/oracle/javacard/api_classic/3.0.5/*.lastUpdated
  mvn -B -q org.apache.maven.plugins:maven-install-plugin:3.1.2:install-file \
    -Dfile="$TOOLS/sdks/$JC_KIT/lib/api_classic.jar" \
    -DgroupId=oracle.javacard -DartifactId=api_classic -Dversion=3.0.5 -Dpackaging=jar \
    -Dmaven.repo.local="$M2_REPO"
else
  log "API Java Card déjà installée"
fi

# 3. jCardSim depuis les sources
JCARDSIM_JAR="$M2_REPO/com/licel/jcardsim/$JCARDSIM_VERSION/jcardsim-$JCARDSIM_VERSION.jar"
if [[ ! -f "$JCARDSIM_JAR" ]]; then
  log "Compilation de jCardSim ($JCARDSIM_COMMIT)"
  rm -rf "$TOOLS/jcardsim"
  git clone --quiet "$JCARDSIM_REPO" "$TOOLS/jcardsim"
  git -C "$TOOLS/jcardsim" checkout --quiet "$JCARDSIM_COMMIT"
  # Comme la CI de jCardSim : "package" seulement. La phase integration-test de son pom
  # utilise maven-antrun-plugin 1.8, qui exige tools.jar (absent depuis le JDK 9).
  # Le jar produit est ensuite installé explicitement dans le dépôt Maven local.
  ( cd "$TOOLS/jcardsim" && \
    JC_CLASSIC_HOME="$TOOLS/sdks/$JC_KIT" \
    mvn -B -q package -DskipTests -Dmaven.javadoc.skip=true -Dmaven.repo.local="$M2_REPO" && \
    mvn -B -q org.apache.maven.plugins:maven-install-plugin:3.1.2:install-file \
      -Dfile="target/jcardsim-$JCARDSIM_VERSION.jar" -DpomFile=pom.xml \
      -Dmaven.repo.local="$M2_REPO" )
else
  log "jCardSim déjà installé"
fi

# 4. ant-javacard (empreinte vérifiée)
if ! echo "$ANT_JAVACARD_SHA256  $TOOLS/ant-javacard.jar" | sha256sum -c --status 2>/dev/null; then
  log "ant-javacard $ANT_JAVACARD_VERSION"
  curl -fsSL -o "$TOOLS/ant-javacard.jar" \
    "https://github.com/martinpaljak/ant-javacard/releases/download/$ANT_JAVACARD_VERSION/ant-javacard.jar"
  echo "$ANT_JAVACARD_SHA256  $TOOLS/ant-javacard.jar" | sha256sum -c --quiet
else
  log "ant-javacard déjà présent"
fi

log "Outillage prêt. Lancez : mvn verify"
