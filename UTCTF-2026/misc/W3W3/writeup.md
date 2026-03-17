# W3W3 - UTCTF 2026

## Challenge Description
The three words I would use to describe this location are...

Flag format: utflag{word1.word2.word3}

## Osint Path
Based on the challenge description, we predicted our task is to correctly figure out where the picture was taken, then find that location on https://what3words.com/

First, take a look at the picture:

![Pic](https://www.notion.so/image/attachment%3A03a04d79-d474-42bf-b8c9-922504818fe3%3AW3W3.jpg?table=block&id=3261b638-5371-80e5-bcfc-e03d475809d6&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

- First, there is an inverted image reflected on the water's surface showing some kind of writing. I predicted this place might be a park or greenspace.
- Next, by reversing each character in the picture, I found a name starting with **"AGUAS DE LIND..."**. I searched the name on Google and found the full name **"AGUAS DE LINDOIA"** — São Paulo, Brazil:

    ![Found](https://www.notion.so/image/attachment%3Abc1e2772-6e39-4830-b0ea-8f031a413e4e%3Aimage.png?table=block&id=3261b638-5371-80d8-af4d-db0d63e5c462&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

- Opening the Pictures tab for this search result, I found an image that exactly matches the symbol in the challenge picture:

    ![Pic-1](https://www.notion.so/image/attachment%3A88eac1e6-aae6-4a1d-ba37-81a5acd6dd21%3Aimage.png?table=block&id=3261b638-5371-80d4-bf40-ef2090edc7bb&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

    ![Correctly](https://thumbs.dreamstime.com/b/ademar-de-barro-square-city-aguas-lindoia-sp-brazil-pra-barros-no-centro-das-guas-da-cidade-lind-ia-com-um-lago-335664985.jpg?w=992)

- Looking closely at the picture, I identified several important points:

    - The symbol is placed on the lake bank, not on an island.
    - In the background, there appears to be a hill and some buildings that look like a resort.
    - The challenge photo may have been taken from the opposite side of the lake bank from the symbol's location.

Next, I used Gemini to list resorts in Águas de Lindoia and found a resort named "Hotel Monte Real":

![gemini](https://www.notion.so/image/attachment%3A2712aaf6-42d6-408d-a888-8fb582e5e11a%3Aimage.png?table=block&id=3261b638-5371-806c-8cb5-dd3f75eb7cbe&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

Checking this result on Google Maps, I found the resort has a large lake, which matches our information:

![resort](https://www.notion.so/image/attachment%3Afef91291-966d-4d8d-b9be-43bf123f1104%3Aimage.png?table=block&id=3261b638-5371-8014-a8af-fbc354afb210&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

Based on the challenge information, I predicted the symbol is in the red zone and the cameraman's position is in the green zone:

![zone](https://www.notion.so/image/attachment%3Ac53d4a9b-07df-4c9b-bf63-7858964b15a1%3Aimage.png?table=block&id=3261b638-5371-8069-b7f7-c33365fc2b8b&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

So I used https://what3words.com/ to brute-force locations along the lake bank in the green zone and found the flag at this location:

![flag](https://www.notion.so/image/attachment%3A4e9ab3c0-edd7-4a8a-94cd-8631a60fdcd3%3Aimage.png?table=block&id=3261b638-5371-80dc-9e56-c309409607c9&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)