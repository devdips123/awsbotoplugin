#!/bin/sh

sudo apt update > /dev/null
[ "$? == 0" ] && echo "[INFO] apt update successful"
sudo apt install docker.io git -y > /dev/null
[ "$? == 0" ] && echo "[INFO] docker install successful"

version=$(sudo docker --version)
echo "[INFO] Docker version = $version"
echo "[INFO] Bootstraping successful"
sudo docker login -u devdips123 -p 'xxxxxx' > /dev/null
[ "$? == 0" ] && echo "[INFO] docker login successful"

echo "[INFO] Pulling docker image"
sudo docker pull biocontainers/blast:v2.2.31_cv2 > /dev/null
[ "$? == 0" ] && echo "[INFO] Image pulled successful"
blast_version=$(sudo docker run biocontainers/blast:v2.2.31_cv2 blastp -version)
echo "[INFO] blast_version = $blast_version"

mkdir -p blast_example
cd blast_example
wget http://www.uniprot.org/uniprot/P04156.fasta -q
[ "$? == 0" ] && echo "[INFO] wget successful"
curl -O ftp://ftp.ncbi.nih.gov/refseq/D_rerio/mRNA_Prot/zebrafish.1.protein.faa.gz -s
[ "$? == 0" ] && echo "[INFO] curl successful"
gunzip zebrafish.1.protein.faa.gz -q -f
echo "[INFO] Running docker"
sudo docker run -v `pwd`:/data/ biocontainers/blast:v2.2.31_cv2 makeblastdb -in zebrafish.1.protein.faa -dbtype prot > /dev/null
sudo docker run -v `pwd`:/data/ biocontainers/blast:v2.2.31_cv2 blastp -query P04156.fasta -db zebrafish.1.protein.faa -out results.txt

#echo "[INFO] Printing the benchmark results"

#cat results.txt

echo "[INFO] Success"
